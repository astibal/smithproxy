#include <nlohmann/json.hpp>

#include <service/core/smithproxy.hpp>
#include <inspect/dns.hpp>
#include <proxy/nbrhood.hpp>


#include <service/http/webhooks.hpp>
#include <service/http/async_request.hpp>
#include <service/http/jsonize.hpp>

#include <unordered_map>
#include <map>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <limits>
#include <memory>
#include <numeric>
#include <string_view>
#include <vector>
#include <arpa/inet.h>


namespace sx::http::webhooks {


    static std::unordered_map<std::string, url_stats> _url_stats;
    static std::mutex _url_stats_lock;

    std::mutex& url_stats_lock() { return  _url_stats_lock; }
    std::unordered_map<std::string, url_stats>& url_stats_map() { return _url_stats; }

    static std::atomic_bool enabled = false;
    static std::string hostid;
    static std::mutex hostid_lock;
    static std::uint64_t stats_updates = 0;
    static refresh_gate accepted_refresh_gate(1);
    static std::mutex protocol_lock;
    static std::string sxbn_callback_url;

    namespace {
        struct timing_samples {
            static constexpr std::size_t window_size = 1024;
            std::uint64_t count = 0;
            double last = 0.0;
            double total = 0.0;
            double minimum = 0.0;
            double maximum = 0.0;
            std::deque<double> recent;

            void add(double value) {
                ++count;
                last = value;
                total += value;
                if(count == 1) minimum = maximum = value;
                else {
                    minimum = std::min(minimum, value);
                    maximum = std::max(maximum, value);
                }
                recent.push_back(value);
                if(recent.size() > window_size) recent.pop_front();
            }

            [[nodiscard]] timing_diagnostics_snapshot snapshot() const {
                timing_diagnostics_snapshot result;
                result.samples = count;
                result.last_ms = last;
                result.average_ms = count ? total / static_cast<double>(count) : 0.0;
                result.min_ms = minimum;
                result.max_ms = maximum;
                if(recent.empty()) return result;

                std::vector<double> sorted(recent.begin(), recent.end());
                std::sort(sorted.begin(), sorted.end());
                const auto middle = sorted.size() / 2;
                result.median_ms = sorted.size() % 2
                    ? sorted[middle]
                    : (sorted[middle - 1] + sorted[middle]) / 2.0;
                const auto p95_index = static_cast<std::size_t>(
                    std::ceil(static_cast<double>(sorted.size()) * 0.95)) - 1;
                result.p95_ms = sorted[std::min(p95_index, sorted.size() - 1)];
                return result;
            }
        };

        struct webhook_runtime_stats {
            std::mutex lock;
            std::uint64_t requests = 0;
            std::uint64_t accepted = 0;
            std::uint64_t rejected = 0;
            std::uint64_t completed = 0;
            std::uint64_t succeeded = 0;
            std::uint64_t failed = 0;
            std::uint64_t asynchronous_requests = 0;
            std::uint64_t waiting_requests = 0;
            std::uint64_t action_requests = 0;
            std::uint64_t content_requests = 0;
            std::uint64_t request_bytes = 0;
            std::uint64_t response_bytes = 0;
            std::uint64_t last_request_ms = 0;
            std::uint64_t last_response_ms = 0;
            long last_status = 0;
            std::string last_error;
            std::map<std::string, std::uint64_t> actions;
            timing_samples total_delay;
            timing_samples queue_delay;
            timing_samples transport_delay;
        } webhook_stats;

        struct webhook_request_trace {
            std::chrono::steady_clock::time_point submitted = std::chrono::steady_clock::now();
            std::optional<std::chrono::steady_clock::time_point> initialized;
        };

        struct sift_runtime_stats {
            std::mutex lock;
            std::uint64_t requests = 0;
            std::uint64_t accepted = 0;
            std::uint64_t rejected = 0;
            std::uint64_t completed = 0;
            std::uint64_t succeeded = 0;
            std::uint64_t failed = 0;
            std::uint64_t action_requests = 0;
            std::uint64_t content_requests = 0;
            std::uint64_t request_bytes = 0;
            std::uint64_t response_bytes = 0;
            std::uint64_t last_request_ms = 0;
            std::uint64_t last_response_ms = 0;
            long last_status = 0;
            std::string last_error;
            double rtt_last_ms = 0.0;
            double rtt_total_ms = 0.0;
            double rtt_min_ms = 0.0;
            double rtt_max_ms = 0.0;
        } sift_stats;

        std::uint64_t wallclock_ms() {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        }

        void webhook_request_started(std::size_t bytes, std::string const& action,
                                     bool waiting, bool content) {
            auto lock = std::scoped_lock(webhook_stats.lock);
            ++webhook_stats.requests;
            ++webhook_stats.actions[action.empty() ? "<unknown>" : action];
            if(waiting) ++webhook_stats.waiting_requests;
            else ++webhook_stats.asynchronous_requests;
            if(content) ++webhook_stats.content_requests;
            else ++webhook_stats.action_requests;
            webhook_stats.request_bytes += bytes;
            webhook_stats.last_request_ms = wallclock_ms();
        }

        void webhook_request_accepted(bool accepted) {
            auto lock = std::scoped_lock(webhook_stats.lock);
            if(accepted) ++webhook_stats.accepted;
            else {
                ++webhook_stats.rejected;
                webhook_stats.last_error = "request was not accepted by the worker";
            }
        }

        void webhook_request_initialized(webhook_request_trace& trace,
                                         std::chrono::steady_clock::time_point now) {
            trace.initialized = now;
            const auto elapsed = std::chrono::duration<double, std::milli>(
                now - trace.submitted).count();
            auto lock = std::scoped_lock(webhook_stats.lock);
            webhook_stats.queue_delay.add(elapsed);
        }

        void webhook_request_completed(sx::http::expected_reply const& reply,
                                       webhook_request_trace const& trace,
                                       std::chrono::steady_clock::time_point now) {
            const auto total = std::chrono::duration<double, std::milli>(
                now - trace.submitted).count();
            auto lock = std::scoped_lock(webhook_stats.lock);
            ++webhook_stats.completed;
            webhook_stats.last_response_ms = wallclock_ms();
            webhook_stats.total_delay.add(total);
            if(trace.initialized) {
                webhook_stats.transport_delay.add(
                    std::chrono::duration<double, std::milli>(now - *trace.initialized).count());
            }
            if(!reply) {
                ++webhook_stats.failed;
                webhook_stats.last_status = 0;
                webhook_stats.last_error = "request completed without a reply";
                return;
            }
            const auto status = reply->response.first;
            webhook_stats.last_status = status;
            webhook_stats.response_bytes += reply->response.second.size();
            if(status >= 200 && status < 300) {
                ++webhook_stats.succeeded;
                webhook_stats.last_error.clear();
            } else {
                ++webhook_stats.failed;
                webhook_stats.last_error = reply->response.second;
                constexpr std::size_t max_error = 240;
                if(webhook_stats.last_error.size() > max_error) {
                    webhook_stats.last_error.resize(max_error);
                    webhook_stats.last_error += "...";
                }
            }
        }

        sx::http::AsyncRequest::reply_hook webhook_tracked_hook(
            sx::http::AsyncRequest::reply_hook hook,
            std::shared_ptr<webhook_request_trace> trace) {
            return [hook = std::move(hook), trace = std::move(trace)](
                    sx::http::expected_reply const& reply) {
                const auto now = std::chrono::steady_clock::now();
                const auto initialization = reply && reply->response.first == -100;
                if(initialization) webhook_request_initialized(*trace, now);
                else webhook_request_completed(reply, *trace, now);
                if(hook) hook(reply);
            };
        }

        bool webhook_emit(std::string payload, std::string const& action,
                          sx::http::AsyncRequest::reply_hook hook, bool content = false) {
            webhook_request_started(payload.size(), action, false, content);
            auto trace = std::make_shared<webhook_request_trace>();
            const auto accepted = sx::http::AsyncRequest::emit(
                payload, webhook_tracked_hook(std::move(hook), std::move(trace)));
            webhook_request_accepted(accepted);
            return accepted;
        }

        void webhook_emit_wait(std::string const& payload, std::string const& action,
                               sx::http::AsyncRequest::reply_hook hook, bool content = false) {
            webhook_request_started(payload.size(), action, true, content);
            webhook_request_accepted(true);
            auto trace = std::make_shared<webhook_request_trace>();
            sx::http::AsyncRequest::emit_wait(
                payload, webhook_tracked_hook(std::move(hook), std::move(trace)));
        }

        void sift_request_started(std::size_t bytes, bool content) {
            auto lock = std::scoped_lock(sift_stats.lock);
            ++sift_stats.requests;
            if(content) ++sift_stats.content_requests;
            else ++sift_stats.action_requests;
            sift_stats.request_bytes += bytes;
            sift_stats.last_request_ms = wallclock_ms();
        }

        void sift_request_accepted(bool accepted) {
            auto lock = std::scoped_lock(sift_stats.lock);
            if(accepted) ++sift_stats.accepted;
            else {
                ++sift_stats.rejected;
                sift_stats.last_error = "request was not accepted by the worker";
            }
        }

        void sift_request_completed(sx::http::expected_reply const& reply,
                                    std::chrono::steady_clock::time_point started) {
            const auto elapsed = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - started).count();
            auto lock = std::scoped_lock(sift_stats.lock);
            ++sift_stats.completed;
            sift_stats.last_response_ms = wallclock_ms();
            sift_stats.rtt_last_ms = elapsed;
            sift_stats.rtt_total_ms += elapsed;
            if(sift_stats.completed == 1) {
                sift_stats.rtt_min_ms = elapsed;
                sift_stats.rtt_max_ms = elapsed;
            } else {
                sift_stats.rtt_min_ms = std::min(sift_stats.rtt_min_ms, elapsed);
                sift_stats.rtt_max_ms = std::max(sift_stats.rtt_max_ms, elapsed);
            }

            if(!reply.has_value()) {
                ++sift_stats.failed;
                sift_stats.last_status = 0;
                sift_stats.last_error = "request completed without a reply";
                return;
            }

            const auto status = reply->response.first;
            sift_stats.last_status = status;
            sift_stats.response_bytes += reply->response.second.size();
            if(status >= 200 && status < 300) {
                ++sift_stats.succeeded;
                sift_stats.last_error.clear();
            } else {
                ++sift_stats.failed;
                sift_stats.last_error = reply->response.second;
                constexpr std::size_t max_error = 240;
                if(sift_stats.last_error.size() > max_error) {
                    sift_stats.last_error.resize(max_error);
                    sift_stats.last_error += "...";
                }
            }
        }

        sx::http::AsyncRequest::reply_hook sift_tracked_hook(
            sx::http::AsyncRequest::reply_hook hook,
            std::chrono::steady_clock::time_point started) {
            return [hook = std::move(hook), started](sx::http::expected_reply const& reply) {
                // AsyncRequest emits an initialization callback with status -100
                // before it performs I/O. It is useful to existing hooks, but it
                // is not a completed request and must not distort Sift RTT/error
                // diagnostics.
                const auto initialization = reply.has_value() &&
                                            reply->response.first == -100;
                if(!initialization) sift_request_completed(reply, started);
                if(hook) hook(reply);
            };
        }
    }

    static std::string active_webhook_url() {
        auto lock = std::scoped_lock(CfgFactory::lock());
        return CfgFactory::get()->settings_webhook.active_url();
    }

    webhook_diagnostics_snapshot webhook_diagnostics() {
        const auto settings = sx::http::AsyncRequest::settings_snapshot();
        const auto binary = binary_content_enabled();
        auto lock = std::scoped_lock(webhook_stats.lock);
        webhook_diagnostics_snapshot result;
        result.enabled = settings.enabled;
        result.verify_tls = settings.verify_tls;
        result.binary_content = binary;
        result.url = settings.url;
        result.timeout_seconds = sx::http::AsyncRequest::config::timeout;
        result.requests = webhook_stats.requests;
        result.accepted = webhook_stats.accepted;
        result.rejected = webhook_stats.rejected;
        result.completed = webhook_stats.completed;
        result.succeeded = webhook_stats.succeeded;
        result.failed = webhook_stats.failed;
        result.asynchronous_requests = webhook_stats.asynchronous_requests;
        result.waiting_requests = webhook_stats.waiting_requests;
        result.action_requests = webhook_stats.action_requests;
        result.content_requests = webhook_stats.content_requests;
        result.request_bytes = webhook_stats.request_bytes;
        result.response_bytes = webhook_stats.response_bytes;
        result.last_request_ms = webhook_stats.last_request_ms;
        result.last_response_ms = webhook_stats.last_response_ms;
        result.last_status = webhook_stats.last_status;
        result.last_error = webhook_stats.last_error;
        result.actions = webhook_stats.actions;
        result.total_delay = webhook_stats.total_delay.snapshot();
        result.queue_delay = webhook_stats.queue_delay.snapshot();
        result.transport_delay = webhook_stats.transport_delay.snapshot();
        return result;
    }

    bool binary_content_enabled() {
        const auto current = active_webhook_url();
        auto lock = std::scoped_lock(protocol_lock);
        return !current.empty() and sxbn_callback_url == current;
    }

    void set_enabled(bool val) {
        enabled.store(val, std::memory_order_release);
    }
    bool is_enabled() {
        return enabled.load(std::memory_order_acquire);
    }
    void set_hostid(std::string const& ref) {
        auto lock = std::scoped_lock(hostid_lock);
        hostid = ref;
    }

    std::string get_hostid() {
        auto lock = std::scoped_lock(hostid_lock);
        return hostid.empty() ? SmithProxy::instance().hostname : hostid;
    }

    bool sift_enabled() {
        auto lock = std::scoped_lock(CfgFactory::lock());
        return CfgFactory::get()->settings_webhook.sift;
    }

    static sx::http::AsyncRequest::request_settings sift_settings();

    sift_diagnostics_snapshot sift_diagnostics() {
        const auto settings = sift_settings();
        auto lock = std::scoped_lock(sift_stats.lock);
        sift_diagnostics_snapshot result;
        result.enabled = settings.enabled;
        result.url = settings.url;
        result.unix_socket_path = settings.unix_socket_path;
        result.timeout_seconds = sx::http::AsyncRequest::config::timeout;
        result.requests = sift_stats.requests;
        result.accepted = sift_stats.accepted;
        result.rejected = sift_stats.rejected;
        result.completed = sift_stats.completed;
        result.succeeded = sift_stats.succeeded;
        result.failed = sift_stats.failed;
        result.action_requests = sift_stats.action_requests;
        result.content_requests = sift_stats.content_requests;
        result.request_bytes = sift_stats.request_bytes;
        result.response_bytes = sift_stats.response_bytes;
        result.last_request_ms = sift_stats.last_request_ms;
        result.last_response_ms = sift_stats.last_response_ms;
        result.last_status = sift_stats.last_status;
        result.last_error = sift_stats.last_error;
        result.rtt_last_ms = sift_stats.rtt_last_ms;
        result.rtt_min_ms = sift_stats.rtt_min_ms;
        result.rtt_max_ms = sift_stats.rtt_max_ms;
        if(sift_stats.completed != 0) {
            result.rtt_average_ms = sift_stats.rtt_total_ms /
                                    static_cast<double>(sift_stats.completed);
        }
        return result;
    }

    static sx::http::AsyncRequest::request_settings sift_settings() {
        sx::http::AsyncRequest::request_settings settings;
        auto lock = std::scoped_lock(CfgFactory::lock());
        auto const& factory = CfgFactory::get();
        settings.enabled = factory->settings_webhook.sift;
        settings.url = factory->settings_webhook.sift_url;
        settings.verify_tls = true;
        settings.bind_interface = factory->settings_webhook.bind_interface;
        settings.unix_socket_path = sx::comm::sift::transport_path();
        std::ostringstream dns;
        for(size_t i = 0; i < factory->db_nameservers.size(); ++i) {
            dns << factory->db_nameservers[i].str_host;
            if(i + 1 < factory->db_nameservers.size()) dns << ',';
        }
        settings.dns_servers = dns.str();
        return settings;
    }

    static nlohmann::json sift_identity() {
        static const nlohmann::json identity = [] {
            std::string tenant;
            std::string instance;

            {
                auto lock = std::scoped_lock(CfgFactory::lock());
                auto const& settings = CfgFactory::get()->settings_webhook;
                tenant = settings.sift_tenant_id;
                instance = settings.sift_instance_id;
            }

            if(tenant.empty()) tenant = "default";
            if(instance.empty()) instance = get_hostid();

            return nlohmann::json{{"tenant", std::move(tenant)},
                                  {"instance", std::move(instance)}};
        }();

        return identity;
    }

    bool send_sift_action(
        std::string const& action, std::string const& action_id,
        nlohmann::json const& details) {
        auto settings = sift_settings();
        if(not settings.enabled or settings.url.empty()) return false;
        nlohmann::json message = {
            {"action", action}, {"id", action_id}, {"source", get_hostid()},
            {"identity", sift_identity()}, {"type", "proxy"}, {"details", details}
        };
        auto encoded = to_string(message);
        sift_request_started(encoded.size(), false);
        const auto started = std::chrono::steady_clock::now();
        const auto accepted = sx::http::AsyncRequest::enqueue(
            std::move(settings), std::move(encoded),
            sift_tracked_hook({}, started));
        sift_request_accepted(accepted);
        return accepted;
    }

    static std::string encode_content(
        std::string const& action_id, nlohmann::json details,
        std::string_view payload) {
        auto& info = details["info"];
        info["payload_encoding"] = "sxbn-001";
        info["payload_length"] = payload.size();
        info.erase("content");
        nlohmann::json metadata = {
            {"action", "connection-content"}, {"id", action_id},
            {"source", get_hostid()}, {"identity", sift_identity()},
            {"type", "proxy"}, {"details", std::move(details)}
        };
        const auto encoded = to_string(metadata);
        if(encoded.size() > std::numeric_limits<std::uint32_t>::max() ||
           payload.size() > std::numeric_limits<std::uint32_t>::max()) return {};
        char prefix[26]{};
        std::snprintf(prefix, sizeof(prefix), "SXBN001:%08X:%08X",
                      static_cast<unsigned>(encoded.size()),
                      static_cast<unsigned>(payload.size()));
        std::string message(prefix, 25);
        message.append(encoded);
        message.append(payload.data(), payload.size());
        return message;
    }

    bool send_sift_content_wait(
        std::string const& action_id, nlohmann::json details,
        std::string_view payload, sx::http::AsyncRequest::reply_hook hook) {
        auto settings = sift_settings();
        if(not settings.enabled or settings.url.empty() or not hook) return false;
        auto message = encode_content(action_id, std::move(details), payload);
        if(message.empty()) return false;
        sift_request_started(message.size(), true);
        sift_request_accepted(true);
        const auto started = std::chrono::steady_clock::now();
        std::stringstream log;
        sx::http::AsyncRequest::emit_url_wait_log(
            settings, message, log, sift_tracked_hook(std::move(hook), started));
        return true;
    }

    struct default_callback {
        default_callback() = default;
        virtual ~default_callback() = default;

        void operator() (sx::http::expected_reply rep) const {

            if(rep.has_value()) {

                auto code = rep.value().response.first;
                if(code > 0) {
                    auto const& url = rep.value().request;
                    {
                        auto lc_ = std::scoped_lock(url_stats_lock());
                        auto& stats = url_stats_map();
                        if (++stats_updates % 64 == 0) {
                            for (auto it = stats.begin(); it != stats.end();) {
                                if (it->second.is_expired()) it = stats.erase(it);
                                else ++it;
                            }
                        }
                        auto& entry = stats[url];
                        entry.url = url;
                        entry.update_incr(code >= 300);
                    }
                    on_reply(rep);
                }
                else {
                    // this is an initialization hook call!
                    on_init(rep);
                }
            }
        }

        virtual void on_reply([[maybe_unused]] sx::http::expected_reply const& rep) const {
            // this cannot be abstract class, it's used with a no-op response
        };
        virtual void on_init([[maybe_unused]] sx::http::expected_reply const& rep) const {
            // this cannot be abstract class, it's used with a no-op response
        };
    };

    void ping() {
        if(enabled) {
            nlohmann::json const info = {
                {"action", "info"}, {"source", get_hostid()}, {"type", "proxy"},
                {"details", {{"protocols", {{"connection-content", {"json-base64", "sxbn-001"}}}}}}
            };
            struct info_callback : public default_callback {
                void on_reply(sx::http::expected_reply const& rep) const override {
                    if(!rep) return;
                    bool accepted = false;
                    if(rep->response.first >= 200 and rep->response.first < 300) {
                        const auto response = nlohmann::json::parse(rep->response.second, nullptr, false);
                        if(!response.is_discarded() and response.value("action", "") == "info-response") {
                            const auto protocols = response.value("protocols", nlohmann::json::object());
                            const auto content = protocols.value("connection-content", nlohmann::json::array());
                            accepted = std::find(content.begin(), content.end(), "sxbn-001") != content.end();
                        }
                    }
                    bool enabled_now = false;
                    bool disabled_now = false;
                    {
                        auto lock = std::scoped_lock(protocol_lock);
                        const auto was_accepted = sxbn_callback_url == rep->request;
                        if(accepted) sxbn_callback_url = rep->request;
                        else if(was_accepted) sxbn_callback_url.clear();
                        enabled_now = accepted and !was_accepted;
                        disabled_now = !accepted and was_accepted;
                    }
                    if(enabled_now) {
                        Log::get()->events().insert(INF,
                            "webhook protocol negotiated: sxbn-001 for connection-content");
                    }
                    if(disabled_now) {
                        Log::get()->events().insert(INF,
                            "webhook protocol fallback: JSON/Base64 connection-content");
                    }
                }
            };
            webhook_emit(to_string(info), "info", info_callback());
            nlohmann::json const ping = {
                                          { "action", "ping" },
                                          {"source", get_hostid() },
                                          {"type", "proxy"},
                                          {"instance", SmithProxy::instance().API.instance_OID() },
                                          {"proxies", SmithProxy::instance().API.proxy_session_connid_list() }
                                        };
            webhook_emit(to_string(ping), "ping", default_callback());
        }
    }

    void ping_plus() {
        if(enabled) {
            nlohmann::json const ping = {
                { "action", "ping" },
                {"source", get_hostid() },
                {"type", "proxy"},
                {"instance", SmithProxy::instance().API.instance_OID() },
                {"proxies", SmithProxy::instance().API.proxy_session_connid_list() },
                {"proxies-plus", SmithProxy::instance().API.proxy_session_connid_list_plus() }
            };
            webhook_emit(to_string(ping), "ping", default_callback());
        }
    }

    struct neighbor_reply : public default_callback {
        void on_init(sx::http::expected_reply const& rep) const override {
            if(rep.has_value()) {
                auto* ctrl = rep->ctrl;
                if(ctrl) {
                    ctrl->set_timeout(60);
                    // This transfer has a 60 s total deadline. Detect a peer
                    // that stops making progress before that deadline rather
                    // than configuring an unreachable 120 s low-speed timer.
                    ctrl->set_stale_detection(30);
                }
            }
        }

        void on_reply(sx::http::expected_reply const& rep) const override {
            if(rep->response.first < 200 || rep->response.first >= 300) return;
            auto const& body = rep->response.second;
            if(not body.empty()) {
                SmithProxy::api().neighbor_update(body);
            }
        }
    };

    void ping_neighbors() {
        if(enabled) {
            std::vector<std::string> hostnames;

            NbrHood::instance().for_each([&hostnames](auto const& n) {
               if(not n.hostname.empty()) hostnames.push_back(n.hostname);
            });

            nlohmann::json const nbr_ping = {
                    { "action", "neighbor" },
                    { "state", "ping" },
                    {"source", get_hostid() },
                    {"type", "proxy"},
                    { "addresses", hostnames }
            };
            webhook_emit(to_string(nbr_ping), "neighbor", neighbor_reply());
        }
    }


    void neighbor_state(std::string const& address_str, std::string const& state) {
        const std::vector<std::string> vec = {address_str,};
        neighbor_state(vec, state);
    }

    void neighbor_state(std::vector<std::string> const& address_vec, std::string const& state) {
        if(enabled) {
            nlohmann::json nbr_update = {
                    { "action", "neighbor" },
                    { "state",  state },
                    {"source",  get_hostid() },
                    {"type",    "proxy"},
                    {"addresses", address_vec }
            };

            webhook_emit(to_string(nbr_update), "neighbor", neighbor_reply());
        }
    }

    static nlohmann::json hostname_info_items(
            std::string const& origin, std::vector<std::string> const& addresses,
            std::string const& hostname) {
        nlohmann::json items = nlohmann::json::array();
        if(origin.empty() or hostname.empty()) return items;

        std::map<std::string, std::vector<std::string>> grouped;
        for(auto const& address: addresses) {
            in_addr ipv4 {};
            in6_addr ipv6 {};
            std::string address_type;
            if(inet_pton(AF_INET, address.c_str(), &ipv4) == 1) {
                address_type = "ipv4";
            }
            else if(inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
                address_type = "ipv6";
            }
            else {
                continue;
            }
            auto& values = grouped[address_type];
            if(std::find(values.begin(), values.end(), address) == values.end()) {
                values.push_back(address);
            }
        }

        for(auto& [address_type, values]: grouped) {
            items.push_back({
                {"origin", origin},
                {"type", address_type},
                {"address", std::move(values)},
                {"hostname", hostname}
            });
        }
        return items;
    }

    static bool send_hostname_info_list(nlohmann::json const& list) {
        if(not enabled or list.empty()) return false;
        send_action("hostname-info", {{"info", {{"list", list}}}});
        return true;
    }

    bool hostname_info(std::string const& origin, std::vector<std::string> const& addresses,
                       std::string const& hostname) {
        return send_hostname_info_list(hostname_info_items(origin, addresses, hostname));
    }

    bool hostname_info_dns_cache() {
        nlohmann::json list = nlohmann::json::array();
        {
            auto lock = std::scoped_lock(DNS::get_dns_lock());
            for(auto const& [_, block]: DNS::get_dns_cache().cache()) {
                auto const response = block->ptr();
                if(not response or response->questions().empty()) continue;
                std::vector<std::string> addresses;
                for(auto const& answer: response->answers()) {
                    if(answer.type_ != A and answer.type_ != AAAA) continue;
                    auto const address = answer.ip(false);
                    if(not address.empty()) addresses.push_back(address);
                }
                auto const items = hostname_info_items(
                    "dns", addresses, response->questions().front().rec_str);
                for(auto const& item: items) list.push_back(item);
            }
        }
        return send_hostname_info_list(list);
    }

    static void send_action_impl(std::string const& action,
                                 std::optional<std::string> const& action_id,
                                 nlohmann::json const& details) {
        if(enabled) {


            std::string msg_str;
            try {
                nlohmann::json msg = {
                        {"action", action},
                        {"source", get_hostid() },
                        {"type",   "proxy"}};

                if(action_id) msg.push_back({"id", *action_id});
                msg.push_back({"details", details});
                msg_str = to_string(msg);
            }
            catch(std::bad_array_new_length const& e) {
                Log::get()->events().insert(ERR, "webhook::send_action failed (bad_array_new_length): action=%s, id=%s: %s", action.c_str(),
                                            action_id.value_or("").c_str(),
                                            e.what());
            }
            catch(std::exception const& e) {
                Log::get()->events().insert(ERR, "webhook::send_action failed(generic exception): action=%s, id=%s: %s", action.c_str(),
                                            action_id.value_or("").c_str(),
                                            e.what());
            }
            catch(...) {
                Log::get()->events().insert(ERR, "webhook::send_action failed(unknown exception): action=%s, id=%s", action.c_str(),
                                            action_id.value_or("").c_str());
            }

            if(not msg_str.empty()) {

                struct action_hook : public default_callback {
                    void on_reply([[maybe_unused]] sx::http::expected_reply const &rep) const override {
                        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        if(rep.has_value() and rep.value().response.first == 202
                           and accepted_refresh_gate.acquire(now)) {
                            ping_plus();
                            ping_neighbors();
                        }
                    }
                };
                webhook_emit(std::move(msg_str), action, action_hook(),
                             action == "connection-content");

            }
        }
    }

    void send_action(std::string const& action, nlohmann::json const& details) {
        send_action_impl(action, std::nullopt, details);
    }

    void send_action(std::string const& action, std::string const& action_id,
                     nlohmann::json const& details) {
        send_action_impl(action, action_id, details);
    }

    // send action and wait - use hook,
    bool send_action_wait(std::string const& action, std::string const& action_id, nlohmann::json const& details,
                          sx::http::AsyncRequest::reply_hook hook) {
        if(enabled and hook) {
            nlohmann::json msg = {
                    {"action", action},
                    {"id", action_id},
                    {"source", get_hostid() },
                    {"type",   "proxy"}};

            msg.push_back({"details", details});
            webhook_emit_wait(
                    to_string(msg), action,
                    [hook = std::move(hook)](sx::http::expected_reply const& reply) {
                        // The negative status is an internal Request setup hook,
                        // not a webhook response for synchronous callers.
                        if(!reply || reply->response.first > 0) hook(reply);
                    }, action == "connection-content");
            return true;
        }
        return false;
    }

    bool send_content_wait(std::string const& action_id, nlohmann::json details,
                           std::string_view payload, sx::http::AsyncRequest::reply_hook hook) {
        if(!enabled or !hook or !binary_content_enabled()) return false;
        auto message = encode_content(action_id, std::move(details), payload);
        if(message.empty()) return false;
        webhook_emit_wait(message, "connection-content",
            [hook = std::move(hook)](sx::http::expected_reply const& reply) {
                if(!reply || reply->response.first > 0) hook(reply);
            }, true);
        return true;
    }
}
