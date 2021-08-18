#ifdef USE_LMHPP

#include <thread>
#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

#include <service/httpd/diag/diag_ssl.hpp>

std::thread* create_httpd_thread(unsigned short port) {
    return new std::thread([port]() {
        HttpService_Status_Ping status_ping;

        lmh::WebServer server(port);
        server.opt_bind_loopback = true;

        HttpService_JsonResponder diag_ssl_cache_stats(
                "GET",
                "/api/diag/ssl/cache/stats",
                [](MHD_Connection* conn) -> HttpService_JsonResponseParams {
                    HttpService_JsonResponseParams ret;
                    ret.response = json_ssl_cache_stats(conn);
                    return ret;
                    }
                );

        server.addController(&status_ping);
        server.addController(&diag_ssl_cache_stats);

        server.handler_should_terminate = []() -> bool {
                return SmithProxy::instance().terminate_flag;
            };
        server.start();
    });

}

#endif