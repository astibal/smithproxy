#include <nlohmann/json.hpp>

#include <service/core/smithproxy.hpp>
#include <service/http/webhooks.hpp>
#include <service/http/async_request.hpp>




namespace sx::http::webhooks {
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
                    [](auto ){
                        // we don't need any response
                    });
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
                    [](auto ){
                        // we don't need any response
                    });
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
                    [](auto reply){
                        // we don't need response
                    });
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
                        if(repl.has_value() and repl.value().first == 202) {
                            ping_plus();
                        }
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
