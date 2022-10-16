#include <thread>
#include <memory>

#include <service/httpd/httpd.hpp>
#include <service/core/smithproxy.hpp>

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


        Http_JsonResponseParams token_protected::operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const {

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
                    else if(not token_cookie.empty() and not token_header.empty()) {

                        // csrf token and header must match
                        if(token_cookie != token_header) return std::nullopt;

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


        Http_JsonResponseParams unprotected::operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const {

            Http_JsonResponseParams ret;

            if (not req.empty()) {
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
            return ret;
        }

    }


    namespace dispatchers {

    using json = nlohmann::json;

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
                                HttpSessions::HEADER_CSRF_TOKEN,
                                token.c_str(), HttpSessions::session_ttl);


            return ss.str();
        };

        static Http_JsonResponder authorize_get(
                "GET",
                "/api/authorize",
                [](MHD_Connection *conn, std::string const& meth, std::string const &req) -> Http_JsonResponseParams {
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

                        auto lc_ = std::scoped_lock(HttpSessions::lock);
                        HttpSessions::access_keys[auth_token]["csrf_token"] = TimedOptional(csrf_token,
                                                                                            HttpSessions::session_ttl);

                        ret.response = {{"auth_token", auth_token},
                                        {"csrf_token", csrf_token}};

                        ret.headers.emplace_back("Set-Cookie", create_auth_cookie_val(auth_token));
                        ret.headers.emplace_back("Set-Cookie", create_token_cookie_val(csrf_token));

                        ret.response_code = MHD_HTTP_OK;
                        return ret;
                    }

                    ret.response_code = MHD_HTTP_FORBIDDEN;
                    return ret;
                });

        static Http_JsonResponder authorize(
                "POST",
                "/api/authorize",
                [](MHD_Connection *conn, std::string const& meth, std::string const &req) -> Http_JsonResponseParams {

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
}
}