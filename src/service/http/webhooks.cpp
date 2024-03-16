#include <nlohmann/json.hpp>

#include <service/core/smithproxy.hpp>
#include <service/http/webhooks.hpp>
#include <service/http/async_request.hpp>

#include <unordered_map>


namespace sx::http::webhooks {


    static std::unordered_map<std::string, url_stats> _url_stats;
    static std::mutex _url_stats_lock;

    std::mutex& url_stats_lock() { return  _url_stats_lock; }
    std::unordered_map<std::string, url_stats>& url_stats_map() { return _url_stats; }

    static std::atomic_bool enabled = false;
    static std::string hostid;

    void set_enabled(bool val) {
        enabled = val;
    }
    bool is_enabled() {
        return enabled;
    }
    void set_hostid(std::string const& ref) {
        hostid = ref;
    }

    std::string const& get_hostid() {
        return hostid.empty() ? SmithProxy::instance().hostname : hostid;
    }

    struct default_callback {

        void operator() (sx::http::expected_reply rep) const {

            if(rep.has_value()) {
                auto const& url = rep.value().request;
                auto lc_ = std::scoped_lock(url_stats_lock());
                auto& entry = url_stats_map()[url];
                entry.url = url;

                bool is_error = false;
                if(auto code = rep.value().response.first; code >= 400) {
                    is_error = true;
                }

                entry.update_incr(is_error);
            }
        }
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


    void neighbor_new(std::string const& address_str) {
        if(enabled) {
            nlohmann::json const nbr_update = {
                                                { "action", "neighbor" },
                                                { "state", "new" },
                                                {"source", get_hostid() },
                                                {"type", "proxy"},
                                                { "address", address_str }
                                              };
            sx::http::AsyncRequest::emit(
                    to_string(nbr_update),
                    default_callback());
        }
    }

    void send_action(std::string const& action, std::string const& action_id, nlohmann::json const& details) {
        if(enabled) {
            nlohmann::json msg = {
                    {"action", action},
                    {"id", action_id},
                    {"source", get_hostid() },
                    {"type",   "proxy"}};

            msg.push_back({"details", details});

            sx::http::AsyncRequest::emit(
                    to_string(msg),
                    [](sx::http::expected_reply repl) {
                        // if not OK but ACCEPTED, they don't have enough of information - send it
                        if(repl.has_value() and repl.value().response.first == 202) {
                            ping_plus();
                        }
                        auto def = default_callback();
                        def(repl);
                    });
        }
    }

    // send action and wait - use hook,
    void send_action_wait(std::string const& action, std::string const& action_id, nlohmann::json const& details,
                          sx::http::AsyncRequest::reply_hook hook) {
        if(enabled) {
            nlohmann::json msg = {
                    {"action", action},
                    {"id", action_id},
                    {"source", get_hostid() },
                    {"type",   "proxy"}};

            msg.push_back({"details", details});
            sx::http::AsyncRequest::emit_wait(
                    to_string(msg),
                    hook);
        }
    }
}
