#ifdef USE_LMHPP

#include <thread>
#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>
#include <service/httpd/handlers/handlers.hpp>
#include <service/httpd/handlers/dispatchers.hpp>

namespace sx::webserver {
    using json = nlohmann::json;


std::thread* create_httpd_thread(unsigned short port) {
    return new std::thread([port]() {

        lmh::WebServer server(port);
        server.options().bind_loopback = HttpSessions::loopback_only;
        server.options().certificate = std::make_pair(
                SSLFactory::factory().config.def_po_key_str,
                SSLFactory::factory().config.def_po_cert_str);

        dispatchers::controller_add_authorization(server);

        dispatchers::controller_add_debug_only(server);
        dispatchers::controller_add_commons(server);
        dispatchers::controller_add_diag(server);
        dispatchers::controller_add_uni(server);

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