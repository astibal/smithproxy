#ifndef DISPATCHERS_HPP_
#define DISPATCHERS_HPP_

#include <memory>

#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <nlohmann/json.hpp>

namespace sx::webserver {
    namespace dispatchers {
        void controller_add_debug_only(lmh::WebServer &server);
        void controller_add_commons(lmh::WebServer &server);
        void controller_add_diag(lmh::WebServer &server);
        void controller_add_uni(lmh::WebServer &server);
        void controller_add_wh_register(lmh::WebServer &server);
        void controller_add_wh_unregister(lmh::WebServer &server);
    }
}

#endif