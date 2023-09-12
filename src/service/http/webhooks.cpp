#include <nlohmann/json.hpp>

#include <service/core/smithproxy.hpp>
#include <service/http/webhooks.hpp>
#include <service/http/async_request.hpp>




namespace sx::http::webhooks {
    static std::atomic_bool enabled = false;

    void set_enabled(bool val) {
        enabled = val;
    }

    void ping() {
        if(enabled) {
            nlohmann::json const ping = {
                                          { "action", "ping" },
                                          {"source", SmithProxy::instance().hostname },
                                          {"type", "proxy"}
                                        };
            sx::http::AsyncRequest::emit(
                    to_string(ping),
                    [](auto reply){
                        // we don't need any response
                    });
        }
    }

    void neighbor_new(std::string const& address_str) {
        if(enabled) {
            nlohmann::json const nbr_update = {
                                                { "action", "new" },
                                                {"source", SmithProxy::instance().hostname },
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
}
