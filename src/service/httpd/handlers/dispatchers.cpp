
#include <service/httpd/handlers/dispatchers.hpp>
#include <service/httpd/handlers/handlers.hpp>

#include <service/httpd/diag/diag_ssl.hpp>
#include <service/httpd/diag/daig_proxy.hpp>

#include <service/httpd/cfg/add.hpp>
#include <service/httpd/cfg/set.hpp>
#include <service/httpd/cfg/get.hpp>

namespace sx::webserver::dispatchers {

    void controller_add_debug_only(lmh::WebServer &server) {
#ifndef BUILD_RELEASE
        static Http_JsonResponder status_ping(
                "POST",
                "/api/status/ping",
                authorized::unprotected(
                        []([[maybe_unused]] MHD_Connection *c, [[maybe_unused]] std::string const &meth, [[maybe_unused]] std::string const &req) -> json {
                            time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
                            return {{"version", SMITH_VERSION},
                                    {"status",     "ok"},
                                    {"uptime",     uptime},
                                    {"uptime_str", uptime_string(uptime)}};
                        }));

        server.addController(&status_ping);
#endif
    }

    void controller_add_diag(lmh::WebServer &server) {

        for(auto const& meth: { "GET", "POST"}) {
            static Http_JsonResponder handler(meth, "/api/diag/ssl/cache/stats",
                                              authorized::token_protected(json_ssl_cache_stats));
            server.addController(&handler);
        }

        for(auto const& meth: {"GET", "POST"}) {
            static Http_JsonResponder handler(
                    meth,
                    "/api/diag/ssl/cache/print",
                    authorized::token_protected(json_ssl_cache_print)
            );
            server.addController(&handler);
        }


        for(auto const& meth: {"GET", "POST"}) {
            static Http_JsonResponder handler(
                    meth,
                    "/api/diag/proxy/session/list",
                    authorized::token_protected(json_proxy_session_list)
            );
            server.addController(&handler);
        }
    }

    void controller_add_uni(lmh::WebServer &server) {
        static Http_JsonResponder cfg_uni_add(
                "POST",
                "/api/config/uni/add",
                authorized::token_protected(&json_add_section_entry)
        );
        server.addController(&cfg_uni_add);

        static Http_JsonResponder cfg_uni_set(
                "POST",
                "/api/config/uni/set",
                authorized::token_protected(&json_set_section_entry)
        );
        server.addController(&cfg_uni_set);


        static Http_JsonResponder cfg_uni_get(
                "POST",
                "/api/config/uni/get",
                authorized::token_protected(&json_get_section_entry)
        );
        server.addController(&cfg_uni_get);
    }
}

