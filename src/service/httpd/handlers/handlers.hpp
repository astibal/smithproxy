#ifndef HANDLERS_HPP_
#define HANDLERS_HPP_

#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <service/core/smithproxy.hpp>
#include <service/httpd/httpd.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <nlohmann/json.hpp>

namespace sx::webserver {

    using json = nlohmann::json;

    namespace authorized {

        struct Actor {
            std::string principal;
            std::string authentication_method;
        };

        namespace detail {
            inline Actor& active_actor() {
                static thread_local Actor actor {"<unknown>", "unknown"};
                return actor;
            }
        }

        // Carries already authenticated audit identity through one synchronous
        // responder call without exposing credentials to business handlers.
        class ActorScope {
        public:
            explicit ActorScope(Actor actor)
                : previous_(std::move(detail::active_actor())) {
                detail::active_actor() = std::move(actor);
            }
            ActorScope(const ActorScope&) = delete;
            ActorScope& operator=(const ActorScope&) = delete;
            ~ActorScope() { detail::active_actor() = std::move(previous_); }

        private:
            Actor previous_;
        };

        enum class Access {
            authenticated,
            standard,
            administrator,
            archive,
        };

        std::string client_address(MHD_Connection* mc);
        inline Actor session_actor(std::string_view auth_token) {
            const auto token = std::string(auth_token);
            auto principal = HttpSessions::table_value(
                token, HttpSessions::ATT_PRINCIPAL);
            auto authentication_method = HttpSessions::table_value(
                token, HttpSessions::ATT_AUTHENTICATION_METHOD);
            if(principal.empty()) principal = "authenticated-session";
            if(authentication_method.empty()) authentication_method = "session";
            return {std::move(principal), std::move(authentication_method)};
        }

        inline Actor api_key_actor() {
            return {"api-key", "api_key"};
        }

        inline const Actor& current_actor() {
            return detail::active_actor();
        }

        // Browser sessions must prove CSRF intent for every state-changing
        // method. GET, HEAD and OPTIONS are the only safe methods here.
        [[nodiscard]] inline bool request_requires_csrf_header(
            std::string_view method) noexcept {
            const bool reads_resource = method == "GET" || method == "HEAD";
            const bool inspects_capabilities = method == "OPTIONS";
            return !reads_resource && !inspects_capabilities;
        }

        template<typename T>
        struct token_protected {
            using the_call = std::function<T(MHD_Connection*, std::string const&, std::string const&)>;

            explicit token_protected(the_call c, Access access = Access::standard)
                : Func(c), required_access_(access) {};
            Http_JsonResponseParams operator()(MHD_Connection *conn, std::string const& meth, std::string const &req) const;

            private:
                the_call Func;
                Access required_access_;
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
        ret.response = {{"error", "access denied"}};
        ret.response_code = MHD_HTTP_UNAUTHORIZED;

        auto validate_and_call = [&](auto const& key, auto const& token) {
            // Validate CSRF first. An invalid request must not extend the
            // lifetime of a privileged archive capability as a side effect.
            bool allowed = false;
            switch(required_access_) {
                case Access::authenticated:
                    allowed = HttpSessions::validate_tokens(key, token);
                    break;
                case Access::standard:
                    allowed = HttpSessions::validate_standard_tokens(key, token);
                    break;
                case Access::administrator:
                    allowed = HttpSessions::validate_admin_tokens(key, token);
                    break;
                case Access::archive:
                    allowed = HttpSessions::validate_archive_tokens(key, token);
                    break;
            }
            if (allowed) {
                const ActorScope actor_scope(session_actor(key));
                if constexpr (std::is_same_v<T, Http_JsonResponseParams>) {
                    ret = Func(conn, meth, req);
                } else {
                    ret.response = Func(conn, meth, req);
                    ret.response_code = MHD_HTTP_OK;
                }
            } else {
                Log::get()->events().insert(ERR, "unauthorized API access attempt using tokens from %s",
                                            client_address(conn).c_str());


                ret.response = {{"error", "access denied"},};
                ret.response_code = MHD_HTTP_UNAUTHORIZED;
            }
        };

        auto validate_api_key_and_call = [&](auto const& key) {
            bool allowed = false;
            switch(required_access_) {
                case Access::authenticated:
                    allowed = HttpSessions::has_any_key(key);
                    break;
                case Access::standard:
                    allowed = HttpSessions::has_standard_key(key);
                    break;
                case Access::administrator:
                    allowed = HttpSessions::has_admin_key(key);
                    break;
                case Access::archive:
                    allowed = HttpSessions::has_archive_key(key);
                    break;
            }
            if (allowed) {
                const ActorScope actor_scope(api_key_actor());
                if constexpr (std::is_same_v<T, Http_JsonResponseParams>) {
                    ret = Func(conn, meth, req);
                } else {
                    ret.response = Func(conn, meth, req);
                    ret.response_code = MHD_HTTP_OK;
                }
            } else {
                Log::get()->events().insert(ERR, "unauthorized API access attempt using API key header from %s",
                                            client_address(conn).c_str());
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

                const bool csrf_required = request_requires_csrf_header(meth);
                if(csrf_required and token_header.empty()) {
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

        auto extract_api_key = [&]() -> std::optional<std::string> {
            auto key = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-API-Key");
            if(key) {
                return std::string(key);
            }
            return std::nullopt;
        };

        if (not req.empty() or meth != "POST") {
            // authenticate using cookies & headers if both set

            if(auto cookies_headers = extract_cookies_headers(); cookies_headers) {

                validate_and_call(cookies_headers.value().first, cookies_headers.value().second);
            }
            else if (auto key = extract_api_key(); key.has_value() and HttpSessions::api_header_allowed() and meth == "GET") {
                // API key is fine only for GET requests
                validate_api_key_and_call(key.value());
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
        else if(meth == "POST") {
            ret.response = Func(conn, meth, req);
            ret.response_code = MHD_HTTP_OK;
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
