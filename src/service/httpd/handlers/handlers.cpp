#include <thread>
#include <memory>

#include <service/httpd/httpd.hpp>
#include <service/core/smithproxy.hpp>

#include <service/httpd/diag/diag_ssl.hpp>
#include <service/httpd/diag/daig_proxy.hpp>

#include <service/httpd/cfg/add.hpp>
#include <service/httpd/cfg/set.hpp>
#include <service/httpd/cfg/get.hpp>

#include <service/httpd/handlers/handlers.hpp>

namespace sx::webserver {

    namespace authorized {

        std::string client_address(MHD_Connection* mc) {
            if(mc) {
                auto* ci = MHD_get_connection_info(mc,MHD_CONNECTION_INFO_CLIENT_ADDRESS);
                if(ci) {
                    if (ci->client_addr) {
                        return SocketInfo::inet_ss_str((sockaddr_storage *) ci->client_addr).c_str();
                    }
                }
            }

            return "<unknown>";
        }


        Http_JsonResponseParams token_protected::operator()(MHD_Connection *conn, std::string const &req) const {

            Http_JsonResponseParams ret;

            if (not req.empty()) {
                ret.response_code = MHD_HTTP_OK;

                try {
                    json jreq = json::parse(req);
                    if (HttpSessions::validate_tokens(
                            jreq[HttpSessions::ATT_AUTH_TOKEN].get<std::string>(),
                            jreq[HttpSessions::ATT_CSRF_TOKEN].get<std::string>())) {
                        ret.response = Func(conn, req);
                        ret.response_code = MHD_HTTP_OK;
                    } else {
                        Log::get()->events().insert(ERR,"unauthorized API access attempt from %s", client_address(conn).c_str());


                        ret.response = {{"error", "access denied"},};
                    }
                }
                catch (json::exception const &) {
                    Log::get()->events().insert(ERR,"malformed API request from %s", client_address(conn).c_str());

                    ret.response = {{"error", "access denied"},};
                }

            }
            return ret;
        }


        Http_JsonResponseParams unprotected::operator()(MHD_Connection *conn, std::string const &req) const {

            Http_JsonResponseParams ret;

            if (not req.empty()) {
                ret.response_code = MHD_HTTP_OK;

                try {
                    json jreq = json::parse(req);
                    ret.response = Func(conn, req);
                    ret.response_code = MHD_HTTP_OK;
                }
                catch (json::exception const &) {
                    ret.response = {{"error", "unknown parameters"},};
                }

            }
            return ret;
        }

    }


    namespace handlers {

    using json = nlohmann::json;

    void controller_add_debug_only(lmh::WebServer &server) {
        #ifndef BUILD_RELEASE
        static Http_JsonResponder status_ping(
                "POST",
                "/api/status/ping",
                authorized::unprotected(
                        []([[maybe_unused]] MHD_Connection *c, [[maybe_unused]] std::string const &req) -> json {
                            time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;
                            return {{"version", SMITH_VERSION},
                                    {"status",     "ok"},
                                    {"uptime",     uptime},
                                    {"uptime_str", uptime_string(uptime)}};
                        }));

        server.addController(&status_ping);
        #endif
    }

    void controller_add_authorization(lmh::WebServer &server) {

        static auto create_auth_cookie_val = [](std::string const& token){
            using samesite_t = HttpSessions::cookie_samesite;

            std::stringstream ss;
            ss << string_format("%s=%s; Max-Age:%d",
                                HttpSessions::COOKIE_AUTH_TOKEN,
                                token.c_str(), HttpSessions::session_ttl);

            if(HttpSessions::COOKIE_SAMESITE != samesite_t::None) {
                ss << "; SameSite=";
                ss << (HttpSessions::COOKIE_SAMESITE == samesite_t::Lax ? "Lax" : "Strict");
            }

            return ss.str();
        };
        static auto create_token_cookie_val = [](std::string const& token){
            std::stringstream ss;
            ss << string_format("__Host-%s=%s; Secure; Path=/",
                                HttpSessions::COOKIE_CSRF_TOKEN,
                                token.c_str(), HttpSessions::session_ttl);


            return ss.str();
        };

        static Http_JsonResponder authorize_get(
                "GET",
                "/api/authorize",
                [](MHD_Connection *conn, std::string const &req) -> Http_JsonResponseParams {
                    Http_JsonResponseParams ret;
                    ret.response_code = MHD_YES;

                    auto key = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "key");
                    bool found = false;
                    if(key){
                        auto lc_ = std::scoped_lock(HttpSessions::lock);
                        found = (HttpSessions::api_keys.find(key) !=
                                 HttpSessions::api_keys.end());
                    }

                    if(found) {
                        auto auth_token = HttpSessions::generate_auth_token();
                        auto csrf_token = HttpSessions::generate_csrf_token();

                        ret.response = {{"auth_token", auth_token},
                                        {"csrf_token", csrf_token}};

                        ret.headers.emplace_back("Set-Cookie", create_auth_cookie_val(auth_token));
                        ret.headers.emplace_back("Set-Cookie", create_token_cookie_val(csrf_token));

                        return ret;
                    }

                    ret.response_code = MHD_HTTP_FORBIDDEN;
                    return ret;
                });

        static Http_JsonResponder authorize(
                "POST",
                "/api/authorize",
                [](MHD_Connection *conn, std::string const &req) -> Http_JsonResponseParams {

                    Http_JsonResponseParams ret;
                    ret.response_code = MHD_YES;

                    if (not req.empty()) {

                        try {
                            json jreq = json::parse(req);
                            bool found = false;
                            {
                                auto lc_ = std::scoped_lock(HttpSessions::lock);
                                found = (HttpSessions::api_keys.find(jreq["access_key"].get<std::string>()) !=
                                         HttpSessions::api_keys.end());
                            }
                            if (found) {

                                auto auth_token = HttpSessions::generate_auth_token();
                                auto csrf_token = HttpSessions::generate_csrf_token();

                                ret.response = {{"auth_token", auth_token},
                                                {"csrf_token", csrf_token}};

                                ret.headers.emplace_back("Set-Cookie", create_auth_cookie_val(auth_token));
                                ret.headers.emplace_back("Set-Cookie", create_token_cookie_val(csrf_token));

                                auto lc_ = std::scoped_lock(HttpSessions::lock);
                                HttpSessions::access_keys[auth_token]["csrf_token"] = TimedOptional(csrf_token,
                                                                                                    HttpSessions::session_ttl);
                            } else {
                                Log::get()->events().insert(ERR, "unauthorized API access attempt from %s",
                                                            authorized::client_address(conn).c_str());

                                ret.response = {{"error", "access denied"},};
                            }
                        }
                        catch (nlohmann::json::exception const &) {

                            Log::get()->events().insert(ERR, "malformed API request from %s",
                                                        authorized::client_address(conn).c_str());
                            ret.response = {{"error", "access denied"},};
                        }
                        ret.response_code = MHD_HTTP_OK;
                    }

                    return ret;
                }
        );

        server.addController(&authorize);
        server.addController(&authorize_get);
    }

    void controller_add_diag(lmh::WebServer &server) {
        static Http_JsonResponder diag_ssl_cache_stats(
                "POST",
                "/api/diag/ssl/cache/stats",
                authorized::token_protected(json_ssl_cache_stats)
        );
        server.addController(&diag_ssl_cache_stats);


        static Http_JsonResponder diag_ssl_cache_print(
                "POST",
                "/api/diag/ssl/cache/print",
                authorized::token_protected(json_ssl_cache_print)
        );
        server.addController(&diag_ssl_cache_print);

        static Http_JsonResponder diag_proxy_session_list(
                "POST",
                "/api/diag/proxy/session/list",
                authorized::token_protected(json_proxy_session_list)
        );
        server.addController(&diag_proxy_session_list);
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
}