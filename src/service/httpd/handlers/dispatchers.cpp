
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

    void controller_add_status(lmh::WebServer &server) {

        for(auto const& meth: { "GET", "POST" }) {
            auto* status_ping = new Http_Responder(
                    meth,
                    "/api/status/ping",
    #ifndef BUILD_RELEASE
                    authorized::unprotected<json>(
    #else
                    authorized::token_protected<json>(
    #endif
                            []([[maybe_unused]] MHD_Connection *c, [[maybe_unused]] std::string const &meth, [[maybe_unused]] std::string const &req) -> json {
                                time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
                                return {{"version", SMITH_VERSION},
                                        {"status",     "ok"},
                                        {"uptime",     uptime},
                                        {"uptime_str", uptime_string(uptime)}};
                            }));

            status_ping->Content_Type = "application/json";
            server.addController(std::shared_ptr<lmh::Controller>(status_ping));
        }
    }

    void controller_add_commons(lmh::WebServer& server) {
        auto* cacert = new Http_Responder(
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

        cacert->Content_Type = "application/x-pem-file";
        server.addController(std::shared_ptr<lmh::Controller>(cacert));
    }


    void controller_add_diag(lmh::WebServer &server) {

        for(auto const& meth: { "GET", "POST"}) {
            auto* handler = new Http_Responder(meth, "/api/diag/ssl/cache/stats",
                                          authorized::token_protected<json>(json_ssl_cache_stats));
            handler->Content_Type = "application/json";
            server.addController(std::shared_ptr<lmh::Controller>(handler));
        }

        for(auto const& meth: {"GET", "POST"}) {
            auto* handler = new Http_Responder(
                    meth,
                    "/api/diag/ssl/cache/print",
                    authorized::token_protected<json>(json_ssl_cache_print)
            );
            handler->Content_Type = "application/json";
            server.addController(std::shared_ptr<lmh::Controller>(handler));
        }


        for(auto const& meth: {"GET", "POST"}) {
            auto* handler = new Http_Responder(
                    meth,
                    "/api/diag/proxy/session/list",
                    authorized::token_protected<json>(json_proxy_session_list)
            );
            handler->Content_Type = "application/json";
            server.addController(std::shared_ptr<lmh::Controller>(handler));
        }

        for(auto const& meth: {"GET", "POST"}) {
            auto* handler = new Http_Responder(
                    meth,
                    "/api/diag/proxy/neighbor/list",
                    authorized::token_protected<json>(json_proxy_neighbor_list)
            );
            handler->Content_Type = "application/json";
            server.addController(std::shared_ptr<lmh::Controller>(handler));
        }

        for(auto const& meth: {"POST"}) {
            auto* handler = new Http_Responder(
                    meth,
                    "/api/diag/proxy/neighbor/update",
                    authorized::token_protected<json>(json_proxy_neighbor_update)
            );
            handler->Content_Type = "application/json";
            server.addController(std::shared_ptr<lmh::Controller>(handler));
        }


        for(auto const& meth: {"GET", "POST"}) {
            auto* handler = new Http_Responder(
                    meth,
                    "/api/do/ssl/custom/reload",
                    authorized::token_protected<json>(json_do_ssl_custom_reload)
            );
            handler->Content_Type = "application/json";
            server.addController(std::shared_ptr<lmh::Controller>(handler));
        }


    }

    void controller_add_uni(lmh::WebServer &server) {
        auto* cfg_uni_add = new Http_Responder(
                "POST",
                "/api/config/uni/add",
                authorized::token_protected<json>(&json_add_section_entry)
        );
        cfg_uni_add->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(cfg_uni_add));

        auto* cfg_uni_set = new Http_Responder(
                "POST",
                "/api/config/uni/set",
                authorized::token_protected<json>(&json_set_section_entry)
        );
        cfg_uni_set->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(cfg_uni_set));


        auto* cfg_uni_get = new Http_Responder(
                "POST",
                "/api/config/uni/get",
                authorized::token_protected<json>(&json_get_section_entry)
        );
        cfg_uni_get->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(cfg_uni_get));
    }

    void controller_add_wh_register(lmh::WebServer& server) {
        auto* webhook_register = new Http_Responder(
                    "POST",
                    "/api/webhook/register",
                    authorized::token_protected<json>(wh_register)
            );
        webhook_register->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(webhook_register));
    }
    void controller_add_wh_unregister(lmh::WebServer& server) {
        auto* webhook_unregister = new Http_Responder(
                "POST",
                "/api/webhook/unregister",
                authorized::token_protected<json>(wh_unregister)
        );
        webhook_unregister->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(webhook_unregister));
    }
}

