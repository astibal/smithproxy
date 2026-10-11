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
            nlohmann::json const ping = {
                                          { "action", "ping" },
                                          {"source", get_hostid() },
                                          {"type", "proxy"},
                                          {"instance", SmithProxy::instance().API.instance_OID() },
                                          {"proxies", SmithProxy::instance().API.proxy_session_connid_list() }
                                        };
            sx::http::AsyncRequest::emit(
                    to_string(ping),
                    default_callback());
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
            sx::http::AsyncRequest::emit(
                    to_string(ping),
                    default_callback());
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
            sx::http::AsyncRequest::emit(
                    to_string(nbr_ping),
                    neighbor_reply());
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

            sx::http::AsyncRequest::emit(
                    to_string(nbr_update),
                    neighbor_reply());
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
                sx::http::AsyncRequest::emit(msg_str, action_hook());

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
            sx::http::AsyncRequest::emit_wait(
                    to_string(msg),
                    [hook = std::move(hook)](sx::http::expected_reply const& reply) {
                        // The negative status is an internal Request setup hook,
                        // not a webhook response for synchronous callers.
                        if(!reply || reply->response.first > 0) hook(reply);
                    });
            return true;
        }
        return false;
    }
}
