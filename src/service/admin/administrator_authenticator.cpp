#include "administrator_authenticator.hpp"

#include <service/cfgapi/cfgapi.hpp>
#include <service/core/authpam.hpp>
#include <service/httpd/httpd.hpp>
#include <service/httpd/login_throttle.hpp>

#include <openssl/crypto.h>

#include <mutex>

namespace sx::admin {
namespace {

struct PamCredentials {
    std::string username;
    std::string password;

    ~PamCredentials() {
        if(!password.empty()) OPENSSL_cleanse(password.data(), password.size());
    }
};

} // namespace

LoginResult authenticate(
    const std::string_view source,
    const std::string_view username,
    const std::string_view password) {
    auto& throttle = sx::webserver::LoginThrottle::instance();
    const auto throttle_decision = throttle.permit(source, username);
    if(!throttle_decision.allowed) {
        return {
            LoginStatus::throttled,
            {},
            {},
            false,
            throttle_decision.retry_after_seconds,
        };
    }

    AuthenticationStatus managed_status = AuthenticationStatus::denied;
    try {
        managed_status = CfgFactory::authenticate_administrator(username, password);
    }
    catch(...) {
        return {LoginStatus::unavailable, {}, {}, false, 0};
    }

    const bool managed_authenticated =
        managed_status == AuthenticationStatus::authenticated;
    if(managed_authenticated) {
        throttle.record_success(source, username);
        return {
            LoginStatus::accepted,
            std::string(username),
            "password",
            true,
        };
    }

    const bool managed_not_configured =
        managed_status == AuthenticationStatus::not_configured;
    [[maybe_unused]] const bool pam_enabled =
        sx::webserver::HttpSessions::pam_login_enabled();
    std::string administrator_group;
    {
        const auto guard = std::scoped_lock(CfgFactory::lock());
        administrator_group = CfgFactory::get()->admin_group;
    }
    if(administrator_group.empty()) administrator_group = "root";

#ifdef USE_PAM
    const PamCredentials credentials{std::string(username), std::string(password)};
    const bool pam_authenticated = pam_enabled && managed_not_configured &&
        sx::auth::pam_auth_user_pass(
            credentials.username.c_str(), credentials.password.c_str()) &&
        sx::auth::unix_is_group_member(
            credentials.username.c_str(), administrator_group.c_str());
#else
    const bool pam_authenticated = false;
#endif
    if(!pam_authenticated)
        return {LoginStatus::rejected, {}, {}, false, 0};

    throttle.record_success(source, username);
    return {
        LoginStatus::accepted,
        std::string(username),
        "pam",
        false,
    };
}

} // namespace sx::admin
