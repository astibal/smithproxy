#include <exception>
#include <memory>
#include <thread>

#include <service/httpd/httpd.hpp>
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

    std::string create_auth_cookie_val(std::string const& token, uint32_t ttl){
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

    std::string create_token_cookie_val(std::string const& token, uint32_t ttl){
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
    };

    static void authorize_response(
        Http_JsonResponseParams& response, bool administrator_access = false,
        bool archive_access = false, std::string administrator = {}) {

        const auto auth_token = HttpSessions::generate_auth_token();
        const auto csrf_token = HttpSessions::generate_csrf_token();

        if(auth_token.empty() || csrf_token.empty()) {
            response.response = {{"error", "secure token generation failed"}};
            response.response_code = MHD_HTTP_SERVICE_UNAVAILABLE;
            return;
        }

        const auto session_guard = std::scoped_lock(HttpSessions::lock);
        const auto ttl = HttpSessions::session_ttl;
        response.response = {
            {"auth_token", auth_token},
            {"csrf_token", csrf_token},
        };
        response.response_code = MHD_HTTP_OK;
        response.headers.emplace_back("Set-Cookie", create_auth_cookie_val(auth_token, ttl));
        response.headers.emplace_back("Set-Cookie", create_token_cookie_val(csrf_token, ttl));
        HttpSessions::access_keys[auth_token]["csrf_token"] = TimedOptional(csrf_token,
                                                                            ttl);
        HttpSessions::access_keys[auth_token]["administrator_access"] = TimedOptional(
            std::string(administrator_access || archive_access ? "1" : "0"), ttl);
        HttpSessions::access_keys[auth_token]["archive_access"] = TimedOptional(
            std::string(archive_access ? "1" : "0"), ttl);
        if(!administrator.empty()) {
            HttpSessions::access_keys[auth_token][HttpSessions::ATT_ADMINISTRATOR_NAME] =
                TimedOptional(std::move(administrator), ttl);
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
        auto administrator_status = sx::admin::AuthenticationStatus::denied;
        try {
            administrator_status = CfgFactory::authenticate_administrator(
                username, password);
        }
        catch(const std::exception& error) {
            Log::get()->events().insert(
                ERR, "administrator authentication unavailable: %s", error.what());
        }

        const bool administrator_authenticated =
            administrator_status == sx::admin::AuthenticationStatus::authenticated;
        const bool administrator_not_configured =
            administrator_status == sx::admin::AuthenticationStatus::not_configured;
        if(administrator_authenticated) {
            authorize_response(response, true, false, username);
            return response;
        }

        [[maybe_unused]] const bool pam_enabled = HttpSessions::pam_login_enabled();
        std::string admin_group;
        {
            const auto guard = std::scoped_lock(CfgFactory::lock());
            admin_group = CfgFactory::get()->admin_group;
        }
        if(admin_group.empty()) admin_group = "root";

#ifdef USE_PAM
        const bool pam_authenticated = pam_enabled && administrator_not_configured &&
            auth::pam_auth_user_pass(username.c_str(), password.c_str()) &&
            auth::unix_is_group_member(username.c_str(), admin_group.c_str());
#else
        const bool pam_authenticated = false;
#endif
        if(pam_authenticated) {
            // Membership in the configured administrative group grants both
            // administrator management and explicit backup/restore access.
            authorize_response(response, true, true);
            return response;
        }

        Log::get()->events().insert(
            ERR, "unauthorized access attempt from %s as user %s",
            authorized::client_address(connection).c_str(), username.c_str());
        return response;
    }

    namespace dispatchers {

    using json = nlohmann::json;

    void controller_add_authorization(lmh::WebServer &server) {

        constexpr std::size_t administrator_request_limit = 16U * 1024U;


        auto* authorize_get = new Http_Responder(
                "GET",
                "/api/authorize",
                [](MHD_Connection *conn, std::string const &meth, std::string const &req) -> Http_JsonResponseParams {
                    Http_JsonResponseParams ret;
                    ret.response_code = MHD_YES;

                    auto key = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "key");
                    bool found = false;
                    if (key) {
                        // Query strings are routinely logged by proxies and
                        // browsers. Never accept an archive key through this
                        // legacy convenience endpoint.
                        found = HttpSessions::has_api_key(key);
                    }

                    if (found) {
                        authorize_response(ret);
                        return ret;
                    }

                    ret.response = {{"error", "access denied"}};
                    ret.response_code = MHD_HTTP_FORBIDDEN;
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
                            json jreq = json::parse(req);
                            bool found = false;
                            const auto access_key =
                                jreq["access_key"].get<std::string>();
                            found = HttpSessions::has_access_key(access_key);
                            if (found) {
                                authorize_response(
                                    ret,
                                    HttpSessions::has_admin_key(access_key),
                                    HttpSessions::has_archive_key(access_key));
                            } else {
                                Log::get()->events().insert(ERR, "unauthorized API access attempt from %s",
                                                            authorized::client_address(conn).c_str());
                            }
                        }
                        catch (nlohmann::json::exception const &) {

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
            authorized::token_protected<Http_JsonResponseParams>(
                administrator_enrollment,
                authorized::Access::administrator));
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
    }
}
}
