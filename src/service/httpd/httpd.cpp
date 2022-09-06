#ifdef USE_LMHPP

#include <thread>
#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

#include <service/httpd/diag/diag_ssl.hpp>
#include <service/httpd/diag/daig_proxy.hpp>

std::thread* create_httpd_thread(unsigned short port) {
    return new std::thread([port]() {
        HttpService_Status_Ping status_ping;

        lmh::WebServer server(port);
        server.options().bind_loopback = true;

        server.addController(&status_ping);

        HttpService_JsonResponder diag_ssl_cache_stats(
                "GET",
                "/api/diag/ssl/cache/stats",
                [](MHD_Connection* conn) -> HttpService_JsonResponseParams {
                    HttpService_JsonResponseParams ret;
                    ret.response = json_ssl_cache_stats(conn);
                    return ret;
                    }
                );
        server.addController(&diag_ssl_cache_stats);


        HttpService_JsonResponder diag_ssl_cache_print(
                "GET",
                "/api/diag/ssl/cache/print",
                [](MHD_Connection* conn) -> HttpService_JsonResponseParams {
                    HttpService_JsonResponseParams ret;
                    ret.response = json_ssl_cache_print(conn);
                    return ret;
                }
                );
        server.addController(&diag_ssl_cache_print);

        HttpService_JsonResponder diag_proxy_session_list(
                "GET",
                "/api/diag/proxy/session/list",
                [](MHD_Connection* conn) -> HttpService_JsonResponseParams {
                    HttpService_JsonResponseParams ret;
                    ret.response = json_proxy_session_list(conn);
                    return ret;
                }
        );
        server.addController(&diag_proxy_session_list);


        server.options().handler_should_terminate = []() -> bool {
                return SmithProxy::instance().terminate_flag;
            };
        server.start();
    });

}

#endif