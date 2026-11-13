#include "proxy/multiflow/mfmitmproxy.hpp"
#include <common/meter.hpp>

#include "proxy/mitmhost.hpp"
#include "proxy/mitmproxy.hpp"
#include "proxy/proxymaker.hpp"
#include "proxy/master_policy.hpp"
#include <inspect/engine/http3_adapter.hpp>
#include <inspect/engine/http3.hpp>
#include <service/http/webhooks.hpp>

#include <masterproxy.hpp>

#include <map>
#include <mutex>
#include <set>

namespace sx::multiflow {
namespace {

/** Readiness demultiplexer used as the Com owned by the transport master. */
class scheduler_com final : public baseCom {
public:
    struct binding {
        std::weak_ptr<connection> owner;
        flow_handle flow;
    };

    baseCom* replicate() override { return new scheduler_com; }
    int connect(const char*, const char*) override { return -1; }
    int accept(int, sockaddr*, socklen_t*) override { return -1; }
    int bind(unsigned short) override { return -1; }
    int bind(const char*) override { return -1; }
    ssize_t read(int, void*, size_t, int) override { return -1; }
    ssize_t peek(int, void*, size_t, int) override { return -1; }
    ssize_t write(int, const void*, size_t, int) override { return -1; }
    void shutdown(int) override {}
    void close(int) override {}
    void cleanup() override {}
    bool is_connected(int token) override { return lookup(token).has_value(); }
    bool in_readset(int token) override {
        auto current = lookup(token);
        auto owner = current ? current->owner.lock() : nullptr;
        return owner && owner->readable(current->flow);
    }
    bool in_writeset(int token) override {
        auto current = lookup(token);
        auto owner = current ? current->owner.lock() : nullptr;
        return owner && owner->writable(current->flow);
    }
    int translate_socket(int) const override { return -1; }
    int poll() override { poll_result = 1; return poll_result; }
    std::string shortname() const override { return "mf-master"; }
    std::string to_string(int) const override { return "MultiFlow scheduler"; }

    void attach(int token, std::shared_ptr<connection> owner, flow_handle flow) {
        std::lock_guard lock(bindings_lock_);
        bindings_[token] = {std::move(owner), flow};
    }

private:
    std::optional<binding> lookup(int token) const {
        std::lock_guard lock(bindings_lock_);
        auto const found = bindings_.find(token);
        return found == bindings_.end() ? std::nullopt
                                        : std::optional<binding>(found->second);
    }

    mutable std::mutex bindings_lock_;
    std::map<int, binding> bindings_;
};

/** One-child master keeps the stock lifecycle without cross-stream spraying. */
class stream_master final : public MasterProxy {
public:
    sx::proxy::policy_state_t policy_state;

    bool run_timers() override {
        const bool tick = MasterProxy::run_timers();
        if(tick) policy_state.validate(*this);
        return tick;
    }

    stream_master() : MasterProxy(new scheduler_com) {}
    scheduler_com& scheduler() const { return *static_cast<scheduler_com*>(com()); }
    void pump() { handle_sockets_once(com()); }
};

struct sift_summary {
    std::mutex lock;
    std::set<std::string> classifications;
    std::set<std::string> lored_classifications;
};

class mitm_flow_proxy final : public flow_proxy {
public:
    mitm_flow_proxy(std::shared_ptr<connection> downstream,
                    std::shared_ptr<connection> upstream,
                    proxy_limits limits, flow_proxy_context context)
        : downstream_(std::move(downstream)), upstream_(std::move(upstream)),
          limits_(limits), context_(std::move(context)) {
        auto alpn = downstream_ ? downstream_->negotiated_alpn() : std::string{};
        if (alpn == "h3") {
            auto const& adapter = sx::engine::http::v3::protocol_adapter();
            protocol_views_ = std::make_shared<sx::engine::ProtocolViews>(adapter);
            auto& ctx = protocol_views_->context(sx::engine::ProtocolEndpoint::Client);
            ctx.negotiated_alpn = std::move(alpn);
            buffer empty;
            adapter.prepare(ctx, true, empty);
            auto& h3 = std::any_cast<sx::engine::http::v3::Http3Connection&>(ctx.state_data);
            h3.on_metadata = [this](std::uint64_t id, nlohmann::json info) {
                // Route using immutable stream identities, never a child pointer:
                // a QPACK callback can describe a sibling while its lock is held.
                auto target = metadata_targets_.find(id);
                if (target == metadata_targets_.end()) return;
                info["session"] = target->second.second;
                info["scope"] = "stream";
                info["parent_id"] = context_.parent_connection_id;
                info["stream_id"] = id;
                info["payload_layer"] = "http3.metadata";
                info["protocol_sequence"] = ++metadata_sequence_;
                nlohmann::json details = {{"info", std::move(info)}};
                if (sx::http::webhooks::is_enabled())
                    sx::http::webhooks::send_action("connection-info", target->second.first, details);
                sx::http::webhooks::send_sift_action("connection-info", target->second.first, details);
            };
            if (context_.rewrite_requested) protocol_views_->enable_rewrite();
        }
    }

    void shutdown() override {
        for(auto& [id, current] : pairs_) {
            current.master->shutdown();
        }
        pairs_.clear();
        metadata_targets_.clear();
        closed_ = true;
    }

    std::size_t pump_once(std::size_t chunk_size) override {
        if (!downstream_ || !upstream_ || chunk_size == 0 || closed_) return 0;
        process_events(true, downstream_->drain_events());
        process_events(false, upstream_->drain_events());
        if (closed_) return 0;

        std::uint64_t uploaded = 0;
        std::uint64_t downloaded = 0;
        for (auto& [id, current] : pairs_) {
            (void)id;
            // Parent counters survive removal of a child inside pump(). They
            // count successful writes, independently of the child's rate meter.
            auto const& stats = current.master->stats();
            auto const up_before = stats.bytes_up();
            auto const down_before = stats.bytes_down();
            current.master->pump();
            uploaded += stats.bytes_up() - up_before;
            downloaded += stats.bytes_down() - down_before;
        }
        auto const now = socle::meter::clock::now();
        if (uploaded) upload_.update(uploaded, now);
        if (downloaded) download_.update(downloaded, now);
        retire_finished();
        return uploaded + downloaded;
    }

    std::size_t pair_count() const override { return pairs_.size(); }
    std::size_t queued_bytes() const override {
        std::size_t result = 0;
        for (auto const& [id, current] : pairs_) {
            (void)id;
            auto lock = std::scoped_lock(current.master->proxy_lock());
            for (auto const& proxy : current.master->proxies()) {
                auto const* mitm = dynamic_cast<MitmProxy const*>(proxy.get());
                if (!mitm) continue;
                if (auto left = mitm->first_left()) result += left->writebuf()->size();
                if (auto right = mitm->first_right()) result += right->writebuf()->size();
            }
        }
        return result;
    }
    std::size_t limit_rejections() const override { return limit_rejections_; }
    std::vector<std::string> render_details(detail_renderer const& render) const override {
        std::vector<std::string> result;

        // The caller runs on the owning QUIC worker; child locks protect rendering.
        for (const auto& [id, current] : pairs_) {
            auto lock = std::scoped_lock(current.master->proxy_lock());
            for (const auto& proxy : current.master->proxies()) {
                if (auto* mitm = dynamic_cast<MitmProxy*>(proxy.get())) {
                    if (auto text = render(mitm)) {
                        result.push_back(std::move(*text));
                    }
                }
            }
        }

        return result;
    }

    flow_summary summary() const override {
        flow_summary result;
        auto policies = policies_;
        std::set<std::string> filters;

        // Retained classifications survive the retirement of individual streams.
        {
            auto lock = std::scoped_lock(sift_summary_->lock);
            result.lored_classifications.assign(sift_summary_->lored_classifications.begin(),
                                               sift_summary_->lored_classifications.end());
        }

        // Traffic and policies survive stream retirement; filters describe live children.
        result.traffic_available = true;
        auto const now = socle::meter::clock::now();
        result.upload_bps = upload_.get(now) * 8;
        result.download_bps = download_.get(now) * 8;
        result.upload_bytes = upload_.total();
        result.download_bytes = download_.total();
        for (const auto& [id, current] : pairs_) {
            auto lock = std::scoped_lock(current.master->proxy_lock());
            for (const auto& proxy : current.master->proxies()) {
                const auto* mitm = dynamic_cast<MitmProxy const*>(proxy.get());
                if (!mitm) {
                    continue;
                }

                policies.insert(mitm->matched_policy());
                for (const auto& [name, filter] : mitm->filters_) {
                    filters.insert(name);
                }
            }
        }

        result.policies.assign(policies.begin(), policies.end());
        result.filters.assign(filters.begin(), filters.end());

        return result;
    }

    std::vector<std::string> sift_classifications() const override {
        auto lock = std::scoped_lock(sift_summary_->lock);
        return {sift_summary_->classifications.begin(), sift_summary_->classifications.end()};
    }

private:
    struct pair {
        flow_handle left;
        flow_handle right;
        std::unique_ptr<stream_master> master;
        bool left_expects_fin = true;
        bool right_expects_fin = true;
        bool left_fin = false;
        bool right_fin = false;
        bool left_finish_sent = false;
        bool right_finish_sent = false;
        std::uint64_t wire_id = 0;
    };

    bool paired(bool left_side, flow_handle flow) const {
        for (auto const& [id, current] : pairs_) {
            (void)id;
            if ((left_side ? current.left : current.right) == flow) return true;
        }
        return false;
    }

    pair* find_pair(bool left_side, flow_handle flow) {
        for (auto& [id, current] : pairs_) {
            (void)id;
            if ((left_side ? current.left : current.right) == flow) return &current;
        }
        return nullptr;
    }

    void process_events(bool from_left, std::vector<event> events) {
        for (auto const& current : events) {
            if (current.type == event_type::connection_close) {
                (from_left ? upstream_ : downstream_)->close(current.protocol_error);
                if (protocol_views_) {
                    buffer empty;
                    const sx::engine::ProtocolInput input{
                        from_left ? sx::engine::ProtocolEndpoint::Client
                                  : sx::engine::ProtocolEndpoint::Server,
                        empty, std::nullopt, sx::engine::ProtocolEvent::ConnectionClose,
                        current.protocol_error};
                    const auto token = protocol_views_->begin(input, 0);
                    protocol_views_->finish(token, input);
                }
                closed_ = true;
                continue;
            }
            if (!current.flow) continue;
            if (current.type == event_type::flow_open && !paired(from_left, *current.flow)) {
                add_stream(from_left, *current.flow);
                continue;
            }
            auto* match = find_pair(from_left, *current.flow);
            if (!match) continue;
            if (current.type == event_type::peer_fin) {
                (from_left ? match->left_fin : match->right_fin) = true;
            } else if (current.type == event_type::reset) {
                auto& destination = from_left ? upstream_ : downstream_;
                destination->reset(from_left ? match->right : match->left,
                                   current.protocol_error);
                auto lock = std::scoped_lock(match->master->proxy_lock());
                for (auto const& proxy : match->master->proxies()) {
                    if (auto* mitm = dynamic_cast<MitmProxy*>(proxy.get())) {
                        mitm->protocol_event(from_left ? FlowCtx::Dir::I2R : FlowCtx::Dir::R2I,
                            sx::engine::ProtocolEvent::Reset, current.protocol_error);
                    }
                    if (proxy) proxy->state().dead(true);
                }
                retired_.insert(match->left.id);
            }
        }
    }

    void add_stream(bool from_left, flow_handle source) {
        auto& source_connection = from_left ? downstream_ : upstream_;
        auto& destination_connection = from_left ? upstream_ : downstream_;
        auto const source_direction = source_connection->direction_of(source);
        if (!source_direction) return;
        if (pairs_.size() >= limits_.max_flows) {
            source_connection->reset(source, 0x107);
            ++limit_rejections_;
            return;
        }

        auto destination_direction = *source_direction;
        if (*source_direction == direction::send_only) destination_direction = direction::receive_only;
        if (*source_direction == direction::receive_only) destination_direction = direction::send_only;
        auto const destination = destination_connection->open_flow(destination_direction);
        if (destination.generation == 0) {
            source_connection->reset(source, 0x102);
            return;
        }

        auto const left_handle = from_left ? source : destination;
        auto const right_handle = from_left ? destination : source;
        auto master = std::make_unique<stream_master>();
        auto* scheduler = &master->scheduler();
        auto* left_com = new MFFlowCom(downstream_, left_handle);
        auto* right_com = new MFFlowCom(upstream_, right_handle);
        // A multiplexed flow is independently half-closed in each direction. The
        // stock MitmProxy treats read()==0 as the end of a TCP session, so the
        // multiflow owner must translate FIN without exposing that EOF early.
        left_com->diagnostic_name(context_.transport_name);
        right_com->diagnostic_name(context_.transport_name);
        left_com->defer_read_eof(true);
        right_com->defer_read_eof(true);
        left_com->master(scheduler);
        right_com->master(scheduler);
        left_com->ingress_ifindex(context_.ingress_ifindex);
        left_com->l3_proto(context_.address_family);
        right_com->l3_proto(context_.address_family);
        scheduler->attach(left_com->token(), downstream_, left_handle);
        scheduler->attach(right_com->token(), upstream_, right_handle);

        auto left = std::make_unique<MitmHostCX>(left_com, left_com->token());
        auto right = std::make_unique<MitmHostCX>(right_com, right_com->token());
        left->host(context_.source_host);
        left->port(context_.source_port);
        right->host(context_.target_host);
        right->port(context_.target_port);
        left->opening(false);
        right->opening(false);

        auto proxy = proxymaker::make(std::move(left), std::move(right));
        if (proxy) {
            // Retain results as they arrive: the master can destroy a child in pump().
            proxy->on_sift_classification = [summary = sift_summary_](std::string const& value) {
                auto lock = std::scoped_lock(summary->lock);
                summary->classifications.insert(value);
            };
            proxy->on_lored_classification = [summary = sift_summary_](std::string const& value) {
                auto lock = std::scoped_lock(summary->lock);
                summary->lored_classifications.insert(value);
            };
        }
        if (proxy && !context_.parent_connection_id.empty()) {
            const auto stream_id = downstream_->wire_flow_id(left_handle).value_or(left_handle.id);
            proxy->webhook_stream = MitmProxy::WebhookStream {
                context_.parent_connection_id, stream_id
            };
        }
        if (proxy && context_.make_traffic_log_adapter) {
            // The downstream ID is the stable identity visible to capture
            // consumers; the paired upstream flow may use a different ID.
            auto const flow_id = downstream_->wire_flow_id(left_handle)
                .value_or(left_handle.id);
            auto adapter = context_.make_traffic_log_adapter(flow_id);

            adapter->on_flow_observation(
                [proxy = proxy.get()](sx::traffic_log_adapter::flow_observation fields) {
                    proxy->submit_flow_observation(std::move(fields), "http3.headers");
                });

            proxy->traffic_log_adapter(std::move(adapter));
        }

        if (proxy && protocol_views_) {
            const auto id = downstream_->wire_flow_id(left_handle).value_or(left_handle.id);
            proxy->bind_protocol(protocol_views_, {id, left_handle.generation});
        }

        if (!proxy || !proxymaker::policy(proxy, false)) {
            source_connection->reset(source, 0x10c);
            return;
        }

        policies_.insert(proxy->matched_policy());

        if (!proxymaker::setup_snat(proxy, context_.source_host, context_.source_port)) {
            source_connection->reset(source, 0x102);
            return;
        }

        // The parent QUIC session has already passed admission. Each logical
        // stream still applies its own policy before inspecting stream data.
        if (!proxymaker::connection_start(*proxy)) {
            proxy->shutdown();
            proxy->finalize();
            source_connection->reset(source, 0x10c);
            destination_connection->reset(destination, 0x10c);
            return;
        }

        if (protocol_views_) {
            const auto id = downstream_->wire_flow_id(left_handle).value_or(left_handle.id);
            metadata_targets_[id] = {proxy->to_connection_ID(), proxy->to_connection_label()};
        }
        master->add_proxy(std::move(proxy));
        auto const left_direction = downstream_->direction_of(left_handle);
        auto const right_direction = upstream_->direction_of(right_handle);
        pairs_.emplace(left_handle.id, pair {
            left_handle,
            right_handle,
            std::move(master),
            left_direction != direction::send_only,
            right_direction != direction::send_only,
            false,
            false,
            false,
            false,
        });
        pairs_.at(left_handle.id).wire_id = downstream_->wire_flow_id(left_handle).value_or(left_handle.id);
    }

    void retire_finished() {
        for (auto& [id, current] : pairs_) {
            auto lock = std::scoped_lock(current.master->proxy_lock());
            for (auto const& proxy : current.master->proxies()) {
                auto* mitm = dynamic_cast<MitmProxy*>(proxy.get());
                if (!mitm) continue;

                auto* left = mitm->first_left();
                auto* right = mitm->first_right();
                if (current.left_fin && !current.right_finish_sent
                    && left && !left->com()->readable(left->socket())
                    && left->to_read().empty() && right && right->writebuf()->empty()) {
                    auto const result = upstream_->finish(current.right);
                    current.right_finish_sent = result != io_status::would_block;
                    if (result == io_status::ok) {
                        mitm->protocol_event(FlowCtx::Dir::I2R, sx::engine::ProtocolEvent::Fin);
                    }
                }
                if (current.right_fin && !current.left_finish_sent
                    && right && !right->com()->readable(right->socket())
                    && right->to_read().empty() && left && left->writebuf()->empty()) {
                    auto const result = downstream_->finish(current.left);
                    current.left_finish_sent = result != io_status::would_block;
                    if (result == io_status::ok) {
                        mitm->protocol_event(FlowCtx::Dir::R2I, sx::engine::ProtocolEvent::Fin);
                    }
                }

                auto const left_complete = !current.left_expects_fin
                    || (current.left_fin && current.right_finish_sent);
                auto const right_complete = !current.right_expects_fin
                    || (current.right_fin && current.left_finish_sent);
                if (left_complete && right_complete) mitm->state().dead(true);
            }
            // FIN is only a hint: MitmProxy may still hold bytes preceding it
            // in a HostCX write buffer. Its normal lifecycle marks/removes the
            // child only after those bytes have been handled.
            if (current.master->proxies().empty()) retired_.insert(id);
        }
        for(auto const id : retired_) {
            const auto found = pairs_.find(id);
            if(found == pairs_.end()) continue;

            found->second.master->shutdown();
            metadata_targets_.erase(found->second.wire_id);
            pairs_.erase(found);
        }
        retired_.clear();
    }

    std::shared_ptr<sift_summary> sift_summary_ = std::make_shared<sift_summary>();
    std::shared_ptr<connection> downstream_;
    std::shared_ptr<connection> upstream_;
    proxy_limits limits_;
    flow_proxy_context context_;
    std::shared_ptr<sx::engine::ProtocolViews> protocol_views_;
    std::map<flow_id, pair> pairs_;
    std::map<std::uint64_t, std::pair<std::string, std::string>> metadata_targets_;
    std::uint64_t metadata_sequence_ = 0;
    std::set<flow_id> retired_;
    std::set<int> policies_;
    std::size_t limit_rejections_ = 0;
    bool closed_ = false;
    socle::meter upload_;
    socle::meter download_;
};

} // namespace

std::unique_ptr<flow_proxy> make_mitm_flow_proxy(
    std::shared_ptr<connection> downstream, std::shared_ptr<connection> upstream,
    proxy_limits limits, flow_proxy_context context) {
    return std::make_unique<mitm_flow_proxy>(std::move(downstream), std::move(upstream),
                                             limits, std::move(context));
}

} // namespace sx::multiflow
