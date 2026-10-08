#ifdef USE_LMHPP

#include <thread>
#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>
#include <service/httpd/handlers/handlers.hpp>
#include <service/httpd/handlers/dispatchers.hpp>

namespace sx::webserver {
    using json = nlohmann::json;


std::thread* create_httpd_thread(unsigned short port, int listener_fd) {
    return new std::thread([port, listener_fd]() {

        lmh::WebServer server(port);
        server.options().bind_loopback = HttpSessions::loopback_only;
        server.options().bind_address = HttpSessions::bind_address;
        server.options().bind_interface = HttpSessions::bind_interface;
        server.options().listen_socket = listener_fd;

        // keep default fail-open, unless config says otherwise
        if(listener_fd < 0 && ! HttpSessions::allowed_ips.empty())
            server.options().allowed_ips = HttpSessions::allowed_ips;

        server.options().certificate = std::make_pair(
                SSLFactory::factory().config.def_po_key_str,
                SSLFactory::factory().config.def_po_cert_str);

        dispatchers::controller_add_authorization(server);

        dispatchers::controller_add_status(server);
        dispatchers::controller_add_commons(server);
        dispatchers::controller_add_diag(server);
        dispatchers::controller_add_uni(server);
        dispatchers::controller_add_wh_register(server);
        dispatchers::controller_add_wh_unregister(server);

        server.options().handler_should_terminate = []() -> bool {
                return SmithProxy::instance().terminate_flag;
            };
        server.start();
        if(listener_fd >= 0) ::close(listener_fd);
    });

}

}
#endif
