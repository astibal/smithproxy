#ifdef USE_LMHPP

#include <thread>
#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

std::thread* create_httpd_thread(unsigned short port) {
    return new std::thread([port]() {
        HttpService_Status_Ping status_ping;

        lmh::WebServer server(port);
        server.addController(&status_ping);
        server.handler_should_terminate = []() -> bool {
                return SmithProxy::instance().terminate_flag;
            };
        server.start();
    });

}

#endif