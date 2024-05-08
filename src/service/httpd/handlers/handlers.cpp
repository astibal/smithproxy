#include <thread>
#include <memory>

#include <service/httpd/httpd.hpp>
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

    std::string create_auth_cookie_val(std::string const& token){
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
    }

    std::string create_token_cookie_val(std::string const& token){
        std::stringstream ss;
        ss << string_format("__Host-%s=%s; Secure; Path=/",
                            HttpSessions::HEADER_CSRF_TOKEN,
                            token.c_str(), HttpSessions::session_ttl);


        return ss.str();
    };

    static void authorize_response(Http_JsonResponseParams& response) {

        auto auth_token = HttpSessions::generate_auth_token();
        auto csrf_token = HttpSessions::generate_csrf_token();

        response.response = {{"auth_token", auth_token},
                        {"csrf_token", csrf_token}};

        response.headers.emplace_back("Set-Cookie", create_auth_cookie_val(auth_token));
        response.headers.emplace_back("Set-Cookie", create_token_cookie_val(csrf_token));

        auto lc_ = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys[auth_token]["csrf_token"] = TimedOptional(csrf_token,
                                                                            HttpSessions::session_ttl);
    }


    namespace dispatchers {

    using json = nlohmann::json;

    void controller_add_authorization(lmh::WebServer &server) {


        auto* authorize_get = new Http_Responder(
                "GET",
                "/api/authorize",
                [](MHD_Connection *conn, std::string const &meth, std::string const &req) -> Http_JsonResponseParams {
                    Http_JsonResponseParams ret;
                    ret.response_code = MHD_YES;

                    auto key = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "key");
                    bool found = false;
                    if (key) {
                        auto lc_ = std::scoped_lock(HttpSessions::lock);
                        found = (HttpSessions::api_keys.find(key) !=
                                 HttpSessions::api_keys.end());
                    }

                    if (found) {
                        authorize_response(ret);

                        ret.response_code = MHD_HTTP_OK;
                        return ret;
                    }

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
                                authorize_response(ret);
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
        authorize->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(authorize));



        auto split_form_data = [](std::string const& str, unsigned char sep1, unsigned char sep2) {
            auto vec = string_split(str, sep1);
            std::map<std::string,std::string> vals;

            if(vec.size() > 1) {
                for(auto const& nv: vec) {
                    auto n_v = string_split(nv, sep2);
                    if(n_v.size() > 1) {
                        vals[n_v[0]] = n_v[1];
                    }
                }
            }

            return vals;
        };

        auto* login = new Http_Responder(
                "POST",
                "/api/login",
                [&split_form_data](MHD_Connection *conn, std::string const &meth, std::string const &req) -> Http_JsonResponseParams {

                    Http_JsonResponseParams ret;
                    ret.response_code = MHD_YES;

                    [[maybe_unused]] bool pam_enabled = HttpSessions::pam_login;
                    std::string admin_group;
                    {
                        auto lc_ = std::scoped_lock(CfgFactory::lock());
                        admin_group = CfgFactory::get()->admin_group;
                    }

                    if (not req.empty()) {

                        //name=a&email=b%40v
                        auto form_map = split_form_data(req,'&','=');
                        try {
                            auto u = form_map.at("username");
                            auto p = form_map.at("password");

                            if(admin_group.empty()) admin_group = "root";

#ifdef USE_PAM
                            if(pam_enabled and auth::pam_auth_user_pass(u.c_str(), p.c_str()) and auth::unix_is_group_member(u.c_str(), admin_group.c_str())) {
#else
                            if(false) {
#endif

                                authorize_response(ret);
                            }
                            else {
                                ret.response_code = MHD_HTTP_UNAUTHORIZED;
                                ret.response = {{"error", "access denied"},};
                                Log::get()->events().insert(ERR, "unauthorized access attempt from %s as user %s (not '%s' group member)",
                                                            authorized::client_address(conn).c_str(),
                                                            u.c_str(),
                                                            admin_group.c_str());

                            }
                        }
                        catch(std::out_of_range const& e) {
                            Log::get()->events().insert(ERR, "unauthorized access attempt from %s",
                                                        authorized::client_address(conn).c_str());

                            ret.response = {{"error", "access denied"},};
                        }

#ifndef USE_PAM
                        Log::get()->events().insert(ERR, "PAM not available: API handler /api/login not supported");
#endif

                        ret.response_code = MHD_HTTP_OK;
                    }

                    return ret;
                }
        );

        login->Content_Type = "application/json";
        server.addController(std::shared_ptr<lmh::Controller>(login));
    }
}
}