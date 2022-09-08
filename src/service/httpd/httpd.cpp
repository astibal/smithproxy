#ifdef USE_LMHPP

#include <thread>
#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

#include <service/httpd/diag/diag_ssl.hpp>
#include <service/httpd/diag/daig_proxy.hpp>

namespace sx::webserver {

using json = nlohmann::json;

std::thread* create_httpd_thread(unsigned short port) {
    return new std::thread([port]() {

        HttpSessions::api_keys.insert("key");

        HttpService_Status_Ping status_ping;

        lmh::WebServer server(port);
        server.options().bind_loopback = true;

        server.addController(&status_ping);

        HttpService_JsonResponder authorize(
                    "POST",
                    "/api/authorize",
                    [](MHD_Connection* conn, std::string const& req) -> HttpService_JsonResponseParams {

                        HttpService_JsonResponseParams ret;
                        ret.response_code = MHD_YES;

                        if(not req.empty()) {

                            try {
                                json jreq = json::parse(req);
                                bool found = false;
                                {
                                    auto lc_ = std::scoped_lock(HttpSessions::lock);
                                    found = ( HttpSessions::api_keys.find(jreq["access_key"].get<std::string>()) != HttpSessions::api_keys.end() );
                                }
                                if (found) {

                                    auto auth_token = HttpSessions::generate_auth_token();
                                    auto csrf_token = HttpSessions::generate_csrf_token();

                                    ret.response = {{"auth_token", auth_token },
                                                    {"csrf_token", csrf_token }};

                                    auto lc_ = std::scoped_lock(HttpSessions::lock);
                                    HttpSessions::access_keys[auth_token]["csrf_token"] = csrf_token;
                                } else {
                                    Log::get()->events().insert(ERR,"API unauthorized access attempt from %s",
                                                                SocketInfo::inet_ss_str((sockaddr_storage*)MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr).c_str());
                                    ret.response = {{"error", "access denied"},};
                                }
                            }
                            catch(nlohmann::json::exception const& e) {
                                ret.response = {{"error", "access denied"},};
                            }
                            ret.response_code = MHD_HTTP_OK;
                        }

                        return ret;
                    }
                );
        server.addController(&authorize);

        HttpService_JsonResponder diag_ssl_cache_stats(
                "POST",
                "/api/diag/ssl/cache/stats",
                [](MHD_Connection* conn, std::string const& req) -> HttpService_JsonResponseParams {
                    HttpService_JsonResponseParams ret;
                    ret.response = json_ssl_cache_stats(conn);
                    return ret;
                    }
                );
        server.addController(&diag_ssl_cache_stats);


        HttpService_JsonResponder diag_ssl_cache_print(
                "POST",
                "/api/diag/ssl/cache/print",
                [](MHD_Connection* conn, std::string const& req) -> HttpService_JsonResponseParams {
                    HttpService_JsonResponseParams ret;
                    ret.response = json_ssl_cache_print(conn);
                    return ret;
                }
                );
        server.addController(&diag_ssl_cache_print);

        HttpService_JsonResponder diag_proxy_session_list(
                "POST",
                "/api/diag/proxy/session/list",
                [](MHD_Connection* conn, std::string const& req) -> HttpService_JsonResponseParams {

                    HttpService_JsonResponseParams ret;

                    if(not req.empty()) {
                        ret.response_code = MHD_HTTP_OK;

                        try {
                            json jreq = json::parse(req);
                            if (HttpSessions::validate_tokens(
                                    jreq[HttpSessions::ATT_AUTH_TOKEN].get<std::string>(),
                                    jreq[HttpSessions::ATT_CSRF_TOKEN].get<std::string>()  )) {
                                ret.response = json_proxy_session_list(conn);
                                ret.response_code = MHD_HTTP_OK;
                            }
                            else {
                                ret.response = {{"error", "access denied"},};
                            }
                        }
                        catch(json::exception const&) {
                            ret.response = {{"error", "access denied"},};
                        }

                    }
                    return ret;
                }
        );
        server.addController(&diag_proxy_session_list);


        server.options().handler_should_terminate = []() -> bool {
                return SmithProxy::instance().terminate_flag;
            };
        if( not server.start()) {
            Log::get()->events().insert(ERR, "failed to start API server");
        }
    });

}

}
#endif