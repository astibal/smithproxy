
#include <service/httpd/handlers/dispatchers.hpp>
#include <service/httpd/handlers/handlers.hpp>

#include <service/httpd/diag/diag_ssl.hpp>
#include <service/httpd/diag/daig_proxy.hpp>

#include <service/httpd/do/do_comands.hpp>

#include <service/httpd/cfg/add.hpp>
#include <service/httpd/cfg/set.hpp>
#include <service/httpd/cfg/get.hpp>

#include <service/httpd/wh/whcontrol.hpp>

namespace sx::webserver::dispatchers {

    void controller_add_debug_only(lmh::WebServer &server) {
#ifndef BUILD_RELEASE
        static Http_Responder status_ping(
                "POST",
                "/api/status/ping",
                authorized::unprotected<json>(
                        []([[maybe_unused]] MHD_Connection *c, [[maybe_unused]] std::string const &meth, [[maybe_unused]] std::string const &req) -> json {
                            time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
                            return {{"version", SMITH_VERSION},
                                    {"status",     "ok"},
                                    {"uptime",     uptime},
                                    {"uptime_str", uptime_string(uptime)}};
                        }));

        status_ping.Content_Type = "application/json";
        server.addController(&status_ping);
#endif
    }

    void controller_add_commons(lmh::WebServer& server) {
        static Http_Responder cacert(
                "GET",
                "/cacert",
                authorized::unprotected<std::string>(
                        []([[maybe_unused]] MHD_Connection *c, [[maybe_unused]] std::string const &meth,
                           [[maybe_unused]] std::string const &req) -> std::string {
                            auto const &fac = SSLFactory::factory();
                            std::string pem_ca_cert;
                            {
                                auto fac_lock = std::scoped_lock(fac.lock());
                                pem_ca_cert = fac.config.def_ca_cert_str;
                            }
                            return pem_ca_cert;
                        }));

        cacert.Content_Type = "application/x-pem-file";
        server.addController(&cacert);
    }


    void controller_add_diag(lmh::WebServer &server) {

        for(auto const& meth: { "GET", "POST"}) {
            static Http_Responder handler(meth, "/api/diag/ssl/cache/stats",
                                          authorized::token_protected<json>(json_ssl_cache_stats));
            handler.Content_Type = "application/json";
            server.addController(&handler);
        }

        for(auto const& meth: {"GET", "POST"}) {
            static Http_Responder handler(
                    meth,
                    "/api/diag/ssl/cache/print",
                    authorized::token_protected<json>(json_ssl_cache_print)
            );
            handler.Content_Type = "application/json";
            server.addController(&handler);
        }


        for(auto const& meth: {"GET", "POST"}) {
            static Http_Responder handler(
                    meth,
                    "/api/diag/proxy/session/list",
                    authorized::token_protected<json>(json_proxy_session_list)
            );
            handler.Content_Type = "application/json";
            server.addController(&handler);
        }

        for(auto const& meth: {"GET", "POST"}) {
            static Http_Responder handler(
                    meth,
                    "/api/diag/proxy/neighbor/list",
                    authorized::token_protected<json>(json_proxy_neighbor_list)
            );
            handler.Content_Type = "application/json";
            server.addController(&handler);
        }

        for(auto const& meth: {"POST"}) {
            static Http_Responder handler(
                    meth,
                    "/api/diag/proxy/neighbor/update",
                    authorized::token_protected<json>(json_proxy_neighbor_update)
            );
            handler.Content_Type = "application/json";
            server.addController(&handler);
        }


        for(auto const& meth: {"GET", "POST"}) {
            static Http_Responder handler(
                    meth,
                    "/api/do/ssl/custom/reload",
                    authorized::token_protected<json>(json_do_ssl_custom_reload)
            );
            handler.Content_Type = "application/json";
            server.addController(&handler);
        }


    }

    void controller_add_uni(lmh::WebServer &server) {
        static Http_Responder cfg_uni_add(
                "POST",
                "/api/config/uni/add",
                authorized::token_protected<json>(&json_add_section_entry)
        );
        cfg_uni_add.Content_Type = "application/json";
        server.addController(&cfg_uni_add);

        static Http_Responder cfg_uni_set(
                "POST",
                "/api/config/uni/set",
                authorized::token_protected<json>(&json_set_section_entry)
        );
        cfg_uni_set.Content_Type = "application/json";
        server.addController(&cfg_uni_set);


        static Http_Responder cfg_uni_get(
                "POST",
                "/api/config/uni/get",
                authorized::token_protected<json>(&json_get_section_entry)
        );
        cfg_uni_get.Content_Type = "application/json";
        server.addController(&cfg_uni_get);
    }

    void controller_add_wh_register(lmh::WebServer& server) {
        static Http_Responder webhook_register(
                    "POST",
                    "/api/webhook/register",
                    authorized::token_protected<json>(wh_register)
            );
        webhook_register.Content_Type = "application/json";
        server.addController(&webhook_register);
    }
    void controller_add_wh_unregister(lmh::WebServer& server) {
        static Http_Responder webhook_unregister(
                "POST",
                "/api/webhook/unregister",
                authorized::token_protected<json>(wh_unregister)
        );
        webhook_unregister.Content_Type = "application/json";
        server.addController(&webhook_unregister);
    }


}

