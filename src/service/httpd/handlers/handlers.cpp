#include <cstdint>
#include <exception>
#include <memory>
#include <thread>

#include <service/httpd/httpd.hpp>
#include <service/admin/administrator_authenticator.hpp>
#include <service/httpd/administrator_api.hpp>
#include <service/httpd/login_request.hpp>
#include <service/core/smithproxy.hpp>

#include <service/httpd/handlers/handlers.hpp>

#include <service/core/authpam.hpp>

namespace sx::webserver {

    namespace authorized {

        std::string client_address(MHD_Connection* mc) {
            if(mc) {
                auto* ci = MHD_get_connection_info(mc,MHD_CONNECTION_INFO_CLIENT_ADDRESS);
                if(ci) {
                    if (ci->client_addr) {
                        return SockOps::ss_str((sockaddr_storage *) ci->client_addr).c_str();
                    }
                }
            }

            return "<unknown>";
        }
    }

    std::string create_auth_cookie_val(std::string const& token, uint32_t ttl) {
        using samesite_t = HttpSessions::cookie_samesite;

        std::stringstream ss;
        ss << string_format("%s=%s; Max-Age=%u; Secure; HttpOnly; Path=/",
                            HttpSessions::COOKIE_AUTH_TOKEN,
                            token.c_str(), ttl);

        if(HttpSessions::COOKIE_SAMESITE != samesite_t::None) {
            ss << "; SameSite=";
            ss << (HttpSessions::COOKIE_SAMESITE == samesite_t::Lax ? "Lax" : "Strict");
        }

        return ss.str();
    }

    std::string create_token_cookie_val(std::string const& token, uint32_t ttl) {
        std::stringstream ss;
        ss << string_format("__Host-%s=%s; Max-Age=%u; Secure; Path=/",
                            HttpSessions::HEADER_CSRF_TOKEN,
                            token.c_str(), ttl);

        if(HttpSessions::COOKIE_SAMESITE != HttpSessions::cookie_samesite::None) {
            ss << "; SameSite=";
            ss << (HttpSessions::COOKIE_SAMESITE == HttpSessions::cookie_samesite::Lax
                   ? "Lax" : "Strict");
        }
        return ss.str();
    }

    struct SessionGrant {
        HttpSessions::AccessCapabilities capabilities;
        std::string principal;
        std::string authentication_method {"api_key"};
        bool managed_administrator {false};
        bool expose_auth_token {true};
        std::uint64_t administrator_generation {0};
    };

    static void authorize_response(
        Http_JsonResponseParams& response, SessionGrant grant = {}) {

        const auto auth_token = HttpSessions::generate_auth_token();
        const auto csrf_token = HttpSessions::generate_csrf_token();

        if(auth_token.empty() || csrf_token.empty()) {
            response.response = {{"error", "secure token generation failed"}};
            response.response_code = MHD_HTTP_SERVICE_UNAVAILABLE;
            return;
        }

        const auto session_guard = std::scoped_lock(HttpSessions::lock);
        const auto ttl = HttpSessions::session_ttl;
        response.response = {{"csrf_token", csrf_token}};
        if(grant.expose_auth_token) response.response["auth_token"] = auth_token;
        response.response_code = MHD_HTTP_OK;
        response.headers.emplace_back("Set-Cookie", create_auth_cookie_val(auth_token, ttl));
        response.headers.emplace_back("Set-Cookie", create_token_cookie_val(csrf_token, ttl));
        HttpSessions::access_keys[auth_token]["csrf_token"] = TimedOptional(csrf_token,
                                                                            ttl);
        HttpSessions::access_keys[auth_token][HttpSessions::ATT_STANDARD_ACCESS] =
            TimedOptional(std::string(grant.capabilities.standard ? "1" : "0"), ttl);
        HttpSessions::access_keys[auth_token][HttpSessions::ATT_ADMINISTRATOR_ACCESS] =
            TimedOptional(std::string(grant.capabilities.administrator ? "1" : "0"), ttl);
        HttpSessions::access_keys[auth_token][HttpSessions::ATT_ARCHIVE_ACCESS] =
            TimedOptional(std::string(grant.capabilities.archive ? "1" : "0"), ttl);
        HttpSessions::access_keys[auth_token][HttpSessions::ATT_AUTHENTICATION_METHOD] =
            TimedOptional(std::move(grant.authentication_method), ttl);
        if(!grant.principal.empty()) {
            HttpSessions::access_keys[auth_token][HttpSessions::ATT_PRINCIPAL] =
                TimedOptional(grant.principal, ttl);
        }
        if(grant.managed_administrator) {
            HttpSessions::access_keys[auth_token][HttpSessions::ATT_ADMINISTRATOR_NAME] =
                TimedOptional(grant.principal, ttl);
            HttpSessions::access_keys[auth_token][HttpSessions::ATT_ADMINISTRATOR_GENERATION] =
                TimedOptional(std::to_string(grant.administrator_generation), ttl);
        }
    }

    static Http_JsonResponseParams login_response(
        MHD_Connection* connection, const std::string&, const std::string& request) {
        Http_JsonResponseParams response;
        response.response = {{"error", "access denied"}};
        response.response_code = MHD_HTTP_UNAUTHORIZED;

        const auto login = parse_login_request(request);
        if(!login.request) return response;

        const auto& username = login.request->username;
        const auto& password = login.request->password;
        const auto administrator_generation =
            HttpSessions::administrator_generation(username);
        const auto source = authorized::client_address(connection);
        const auto authentication = sx::admin::authenticate(source, username, password);
        if(authentication.status == sx::admin::LoginStatus::throttled) {
            response.response_code = MHD_HTTP_TOO_MANY_REQUESTS;
            response.headers.emplace_back(
                MHD_HTTP_HEADER_RETRY_AFTER,
                std::to_string(authentication.retry_after_seconds));
            Log::get()->events().insert(
                WAR, "administrator login throttled from %s as user %s",
                source.c_str(), username.c_str());
            return response;
        }
        if(authentication.status == sx::admin::LoginStatus::unavailable) {
            Log::get()->events().insert(
                ERR, "administrator authentication unavailable for user %s",
                username.c_str());
            return response;
        }

        if(authentication.status == sx::admin::LoginStatus::accepted) {
            SessionGrant grant;
            grant.capabilities.standard = true;
            grant.capabilities.administrator = true;
            grant.principal = authentication.identity;
            grant.authentication_method = authentication.authentication_method;
            grant.managed_administrator = authentication.managed_administrator;
            grant.expose_auth_token = false;
            if(grant.managed_administrator)
                grant.administrator_generation = administrator_generation;
            authorize_response(response, std::move(grant));
            return response;
        }

        Log::get()->events().insert(
            ERR, "unauthorized access attempt from %s as user %s",
            source.c_str(), username.c_str());
        return response;
    }

    static std::string request_auth_token(
        MHD_Connection* connection, const std::string& request) {
        const auto* cookie = MHD_lookup_connection_value(
            connection, MHD_COOKIE_KIND, HttpSessions::COOKIE_AUTH_TOKEN);
        if(cookie && *cookie) return cookie;

        try {
            const auto document = json::parse(request);
            const auto token = document.find(HttpSessions::ATT_AUTH_TOKEN);
            const bool valid_token = token != document.end() && token->is_string();
            return valid_token ? token->get<std::string>() : std::string{};
        }
        catch(const json::exception&) {
            return {};
        }
    }

    static Http_JsonResponseParams logout_response(
        MHD_Connection* connection, const std::string&, const std::string& request) {
        const auto token = request_auth_token(connection, request);
        HttpSessions::revoke_session(token);

        Http_JsonResponseParams response;
        response.response_code = MHD_HTTP_OK;
        response.content_type = "application/json";
        response.response = {{"state", "logged_out"}};
        response.headers.emplace_back("Set-Cookie", create_auth_cookie_val({}, 0));
        response.headers.emplace_back("Set-Cookie", create_token_cookie_val({}, 0));
        return response;
    }

    static Http_JsonResponseParams session_response(
        MHD_Connection* connection, const std::string&, const std::string& request) {
        const auto token = request_auth_token(connection, request);
        const auto* api_key = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "X-API-Key");
        const bool header_authenticated = token.empty() && api_key && *api_key;

        std::string principal;
        std::string authentication_method;
        bool standard_access = false;
        bool administrator_access = false;
        bool archive_access = false;
        if(header_authenticated) {
            authentication_method = "api_key";
            const auto capabilities = HttpSessions::key_capabilities(api_key);
            standard_access = capabilities.standard;
            administrator_access = capabilities.administrator;
            archive_access = capabilities.archive;
        }
        else {
            principal = HttpSessions::table_value(token, HttpSessions::ATT_PRINCIPAL);
            authentication_method = HttpSessions::table_value(
                token, HttpSessions::ATT_AUTHENTICATION_METHOD);
            standard_access = HttpSessions::table_value(
                token, HttpSessions::ATT_STANDARD_ACCESS) == "1";
            administrator_access = HttpSessions::table_value(
                token, HttpSessions::ATT_ADMINISTRATOR_ACCESS) == "1";
            archive_access = HttpSessions::table_value(
                token, HttpSessions::ATT_ARCHIVE_ACCESS) == "1";
        }

        Http_JsonResponseParams response;
        response.response_code = MHD_HTTP_OK;
        response.content_type = "application/json";
        response.response = {
            {"state", "ready"},
            {"authenticated", true},
            {"authentication_method", authentication_method},
            {"capabilities", {
                {"standard", standard_access},
                {"administrator", administrator_access},
                {"archive", archive_access},
            }},
        };
        if(!principal.empty()) response.response["principal"] = std::move(principal);
        return response;
    }

    namespace dispatchers {

    using json = nlohmann::json;

    void controller_add_authorization(lmh::WebServer &server) {
        constexpr std::size_t administrator_request_limit = 16U * 1024U;
        auto* authorize_get = new Http_Responder(
                "GET",
                "/api/authorize",
                [](MHD_Connection *, std::string const &, std::string const &) -> Http_JsonResponseParams {
                    Http_JsonResponseParams ret;
                    ret.response = {
                            {"error", "query-string authorization is disabled; use POST"}
                    };
                    ret.response_code = MHD_HTTP_METHOD_NOT_ALLOWED;
                    ret.headers.emplace_back(MHD_HTTP_HEADER_ALLOW, "POST");
                    return ret;
                });
        authorize_get->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(authorize_get));

        auto* authorize = new Http_Responder(
                "POST",
                "/api/authorize",
                [](MHD_Connection *conn, std::string const &meth, std::string const &req) -> Http_JsonResponseParams {

                    Http_JsonResponseParams ret;
                    ret.response = {{"error", "access denied"}};
                    ret.response_code = MHD_HTTP_UNAUTHORIZED;

                    if (not req.empty()) {

                        try {
                            const auto document = json::parse(req);
                            const auto access_key = document["access_key"].get<std::string>();
                            const auto capabilities =
                                HttpSessions::key_capabilities(access_key);
                            const bool recognized_key = capabilities.any();
                            if(recognized_key) {
                                SessionGrant grant;
                                grant.capabilities = capabilities;
                                authorize_response(ret, std::move(grant));
                            }
                            else {
                                Log::get()->events().insert(
                                    ERR, "unauthorized API access attempt from %s",
                                    authorized::client_address(conn).c_str());
                            }
                        }
                        catch(const nlohmann::json::exception&) {

                            Log::get()->events().insert(ERR, "malformed API request from %s",
                                                        authorized::client_address(conn).c_str());
                        }
                    }

                    return ret;
                }
        );
        authorize->Content_Type = "application/json";
        authorize->Max_Request_Body_Size = administrator_request_limit;
        server.addController(std::shared_ptr<lmh::Controller>(authorize));

        auto* admin_enrollment = new Http_Responder(
            "POST",
            "/api/admin/enrollment/consume",
            administrator_enrollment);
        admin_enrollment->Content_Type = "application/json";
        admin_enrollment->Max_Request_Body_Size = administrator_request_limit;
        server.addController(std::shared_ptr<lmh::Controller>(admin_enrollment));

        for(const auto* method : {"GET", "POST", "DELETE"}) {
            auto* administrators = new Http_Responder(
                method,
                "/api/admin/administrators",
                authorized::token_protected<Http_JsonResponseParams>(
                    administrator_collection,
                    authorized::Access::administrator));
            administrators->Content_Type = "application/json";
            administrators->Max_Request_Body_Size = administrator_request_limit;
            server.addController(std::shared_ptr<lmh::Controller>(administrators));
        }

        auto* administrator_password_handler = new Http_Responder(
            "PUT",
            "/api/admin/administrators/password",
            authorized::token_protected<Http_JsonResponseParams>(
                administrator_password,
                authorized::Access::administrator));
        administrator_password_handler->Content_Type = "application/json";
        administrator_password_handler->Max_Request_Body_Size =
            administrator_request_limit;
        server.addController(
            std::shared_ptr<lmh::Controller>(administrator_password_handler));

        auto* administrator_enabled_handler = new Http_Responder(
            "PATCH",
            "/api/admin/administrators/enabled",
            authorized::token_protected<Http_JsonResponseParams>(
                administrator_enabled,
                authorized::Access::administrator));
        administrator_enabled_handler->Content_Type = "application/json";
        administrator_enabled_handler->Max_Request_Body_Size =
            administrator_request_limit;
        server.addController(
            std::shared_ptr<lmh::Controller>(administrator_enabled_handler));

        auto* login = new Http_Responder("POST", "/api/login", login_response);
        login->Content_Type = "application/json";
        login->Max_Request_Body_Size = administrator_request_limit;
        server.addController(std::shared_ptr<lmh::Controller>(login));

        auto* logout = new Http_Responder(
            "POST", "/api/logout",
            authorized::token_protected<Http_JsonResponseParams>(
                logout_response, authorized::Access::authenticated));
        logout->Content_Type = "application/json";
        logout->Max_Request_Body_Size = administrator_request_limit;
        server.addController(std::shared_ptr<lmh::Controller>(logout));

        auto* session = new Http_Responder(
            "GET", "/api/session",
            authorized::token_protected<Http_JsonResponseParams>(
                session_response, authorized::Access::authenticated));
        session->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(session));
    }
}
}
