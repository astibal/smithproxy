#ifndef HANDLERS_HPP_
#define HANDLERS_HPP_

#include <memory>

#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <ext/json/json.hpp>

namespace sx::webserver {

    using json = nlohmann::json;

    namespace authorized {

        std::string client_address(MHD_Connection* mc);

        struct token_protected {
            using json_call = std::function<json(MHD_Connection*, std::string const&, std::string const&)>;

            explicit token_protected(json_call c) : Func(c) {};
            Http_JsonResponseParams operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const;

            private:
                json_call Func;
        };

        struct unprotected {
            using json_call = std::function<json(MHD_Connection*, std::string const&, std::string const&)>;

            explicit unprotected(json_call c) : Func(c) {};
            Http_JsonResponseParams operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const;

            private:
                json_call Func;
        };
    }

    namespace dispatchers {
        void controller_add_authorization(lmh::WebServer &server);
    }
}

#endif