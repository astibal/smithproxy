#include "proxy/multiflow/mfmitmproxy.hpp"

#include "proxy/mitmhost.hpp"
#include "proxy/mitmproxy.hpp"
#include "proxy/proxymaker.hpp"

#include <masterproxy.hpp>

#include <map>
#include <mutex>
#include <set>
#include <charconv>

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
    stream_master() : MasterProxy(new scheduler_com) {}
    scheduler_com& scheduler() const { return *static_cast<scheduler_com*>(com()); }
    void pump() { handle_sockets_once(com()); }
};

class mitm_flow_proxy final : public flow_proxy {
public:
    mitm_flow_proxy(std::shared_ptr<connection> downstream,
                    std::shared_ptr<connection> upstream,
                    proxy_limits limits, quic::flow_proxy_context context)
        : downstream_(std::move(downstream)), upstream_(std::move(upstream)),
          limits_(limits), context_(std::move(context)) {}

    std::size_t pump_once(std::size_t chunk_size) override {
        if (!downstream_ || !upstream_ || chunk_size == 0 || closed_) return 0;
        process_events(true, downstream_->drain_events());
        process_events(false, upstream_->drain_events());
        if (closed_) return 0;

        auto const before = total_bytes();
        for (auto& [id, current] : pairs_) {
            (void)id;
            current.master->pump();
        }
        auto const after = total_bytes();
        retire_finished();
        return after >= before ? after - before : 0;
    }

    std::size_t pair_count() const override { return pairs_.size(); }
    std::size_t queued_bytes() const override {
        std::size_t result = 0;
        for (auto const& [id, current] : pairs_) {
            (void)id;
            auto lock = std::scoped_lock(current.master->proxy_lock());
            for (auto const& [proxy, thread] : current.master->proxies()) {
                (void)thread;
                auto const* mitm = dynamic_cast<MitmProxy const*>(proxy.get());
                if (!mitm) continue;
                if (auto left = mitm->first_left()) result += left->writebuf()->size();
                if (auto right = mitm->first_right()) result += right->writebuf()->size();
            }
        }
        return result;
    }
    std::size_t limit_rejections() const override { return limit_rejections_; }

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
                for (auto const& [proxy, thread] : match->master->proxies()) {
                    (void)thread;
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
        // A multiplexed stream is independently half-closed in each direction.
        // The stock MitmProxy treats read()==0 as the end of a TCP session, so
        // the multiflow owner must translate FIN without exposing that EOF early.
        left_com->defer_read_eof(true);
        right_com->defer_read_eof(true);
        left_com->master(scheduler);
        right_com->master(scheduler);
        left_com->l3_proto(context_.address_family);
        right_com->l3_proto(context_.address_family);
        scheduler->attach(left_com->token(), downstream_, left_handle);
        scheduler->attach(right_com->token(), upstream_, right_handle);

        auto* left = new MitmHostCX(left_com, left_com->token());
        auto* right = new MitmHostCX(right_com, right_com->token());
        left->host(context_.source_host);
        left->port(context_.source_port);
        right->host(context_.target_host);
        right->port(context_.target_port);
        left->opening(false);
        right->opening(false);

        auto proxy = proxymaker::make(left, right);
        if (!proxy || !proxymaker::policy(proxy, false)) {
            source_connection->reset(source, 0x10c);
            return;
        }
        unsigned int parsed_port = 0;
        auto const* port_begin = context_.target_port.data();
        auto const* port_end = port_begin + context_.target_port.size();
        auto const parse_result = std::from_chars(port_begin, port_end, parsed_port);
        auto const target_port = parse_result.ec == std::errc() && parse_result.ptr == port_end
                              && parsed_port <= 65535
            ? static_cast<unsigned short>(parsed_port) : 0;
        if (!proxymaker::authorize(proxy) && !proxymaker::is_replaceable(target_port)) {
            source_connection->reset(source, 0x10c);
            return;
        }
        if (!proxymaker::setup_snat(proxy, context_.source_host, context_.source_port)) {
            source_connection->reset(source, 0x102);
            return;
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
    }

    std::uint64_t total_bytes() const {
        std::uint64_t result = 0;
        for (auto const& [id, current] : pairs_) {
            (void)id;
            auto lock = std::scoped_lock(current.master->proxy_lock());
            for (auto const& [proxy, thread] : current.master->proxies()) {
                (void)thread;
                if (proxy) {
                    result += proxy->stats().mtr_up.total() + proxy->stats().mtr_down.total();
                }
            }
        }
        return result;
    }

    void retire_finished() {
        for (auto& [id, current] : pairs_) {
            auto lock = std::scoped_lock(current.master->proxy_lock());
            for (auto const& [proxy, thread] : current.master->proxies()) {
                (void)thread;
                auto* mitm = dynamic_cast<MitmProxy*>(proxy.get());
                if (!mitm) continue;

                auto* left = mitm->first_left();
                auto* right = mitm->first_right();
                if (current.left_fin && !current.right_finish_sent
                    && right && right->writebuf()->empty()) {
                    auto const result = upstream_->finish(current.right);
                    current.right_finish_sent = result != io_status::would_block;
                }
                if (current.right_fin && !current.left_finish_sent
                    && left && left->writebuf()->empty()) {
                    auto const result = downstream_->finish(current.left);
                    current.left_finish_sent = result != io_status::would_block;
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
        for (auto const id : retired_) pairs_.erase(id);
        retired_.clear();
    }

    std::shared_ptr<connection> downstream_;
    std::shared_ptr<connection> upstream_;
    proxy_limits limits_;
    quic::flow_proxy_context context_;
    std::map<flow_id, pair> pairs_;
    std::set<flow_id> retired_;
    std::size_t limit_rejections_ = 0;
    bool closed_ = false;
};

} // namespace

std::unique_ptr<flow_proxy> make_mitm_flow_proxy(
    std::shared_ptr<connection> downstream, std::shared_ptr<connection> upstream,
    proxy_limits limits, quic::flow_proxy_context context) {
    return std::make_unique<mitm_flow_proxy>(std::move(downstream), std::move(upstream),
                                             limits, std::move(context));
}

} // namespace sx::multiflow
