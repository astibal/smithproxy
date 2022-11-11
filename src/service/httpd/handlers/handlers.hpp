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

        template<typename T>
        struct token_protected {
            using the_call = std::function<T(MHD_Connection*, std::string const&, std::string const&)>;

            explicit token_protected(the_call c) : Func(c) {};
            Http_JsonResponseParams operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const;

            private:
                the_call Func;
        };

        template<typename T>
        struct unprotected {
            using the_call = std::function<json(MHD_Connection*, std::string const&, std::string const&)>;

            explicit unprotected(the_call c) : Func(c) {};
            Http_JsonResponseParams operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const;

            private:
                the_call Func;
        };
    }

    namespace dispatchers {
        void controller_add_authorization(lmh::WebServer &server);
    }
}


namespace sx::webserver::authorized {
    template<typename T>
    Http_JsonResponseParams token_protected<T>::operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const {

        Http_JsonResponseParams ret;

        auto validate_and_call = [&](auto const& key, auto const& token) {
            if (HttpSessions::validate_tokens(key, token)
                    ) {
                ret.response = Func(conn, meth, req);
                ret.response_code = MHD_HTTP_OK;
            } else {
                Log::get()->events().insert(ERR, "unauthorized API access attempt from %s",
                                            client_address(conn).c_str());


                ret.response = {{"error", "access denied"},};
            }
        };

        auto char_to_str = [](const char* cstr) -> std::string {
            if(not cstr) return {};

            return std::string(cstr);
        };

        auto extract_cookies_headers = [&]() -> std::optional<std::pair<std::string, std::string>> {
            std::string auth_cookie = char_to_str(MHD_lookup_connection_value(conn, MHD_COOKIE_KIND, HttpSessions::COOKIE_AUTH_TOKEN));

            std::string token_cookie_name("__Host-");
            token_cookie_name += HttpSessions::HEADER_CSRF_TOKEN;

            // token cookie is optional, however if set, it must be the same as header
            std::string token_cookie = char_to_str(MHD_lookup_connection_value(conn, MHD_COOKIE_KIND, token_cookie_name.c_str()));

            if(not auth_cookie.empty()) {
                std::string token_header = char_to_str(MHD_lookup_connection_value(conn, MHD_HEADER_KIND, HttpSessions::HEADER_CSRF_TOKEN));

                // POST is required to have CSRF header
                if(meth == "POST" and token_header.empty()) {
                    return std::nullopt;
                }
                else if(not token_header.empty()) {

                    // csrf token and header must match
                    if(not token_cookie.empty() and token_cookie != token_header) return std::nullopt;

                    // prepare for return value
                    token_cookie = token_header;
                }
            }

            if(auth_cookie.empty() or token_cookie.empty())
                return std::nullopt;

            return std::make_optional<std::pair<std::string, std::string>>(auth_cookie, token_cookie);
        };

        if (not req.empty() or meth != "POST") {
            ret.response_code = MHD_HTTP_OK;

            // authenticate using cookies & headers if both set

            if(auto cookies_headers = extract_cookies_headers(); cookies_headers) {

                validate_and_call(cookies_headers.value().first, cookies_headers.value().second);
            }
            else {
                try {
                    json jreq = json::parse(req);
                    auto key = jreq[HttpSessions::ATT_AUTH_TOKEN].get<std::string>();
                    auto token = jreq[HttpSessions::ATT_CSRF_TOKEN].get<std::string>();

                    validate_and_call(key, token);
                }
                catch (json::exception const &) {
                    Log::get()->events().insert(ERR, "malformed API request from %s", client_address(conn).c_str());

                    ret.response = {{"error", "access denied"},};
                }
            }
        }
        return ret;
    }


    template<typename T>
    Http_JsonResponseParams unprotected<T>::operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const {

        Http_JsonResponseParams ret;

        if (meth == "POST" and not req.empty()) {
            ret.response_code = MHD_HTTP_OK;

            try {
                json jreq = json::parse(req);
                ret.response = Func(conn, meth, req);
                ret.response_code = MHD_HTTP_OK;
            }
            catch (json::exception const &) {
                ret.response = {{"error", "unknown parameters"},};
            }

        }
        else if(meth != "POST") {
            // we don't require json in other methods
            ret.response = Func(conn, meth, req);
            ret.response_code = MHD_HTTP_OK;
        }
        return ret;
    }
}

#endif