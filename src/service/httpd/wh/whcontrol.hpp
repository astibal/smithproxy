#include <nlohmann/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/util.hpp>
#include <service/http/jsonize.hpp>

#include <service/cfgapi/cfgapi.hpp>
#include <service/httpd/wh/webhook_lease.hpp>

namespace {
sx::webserver::WebhookOverrideLease& webhook_v2_lease() {
    static sx::webserver::WebhookOverrideLease lease;
    return lease;
}

std::mutex& webhook_control_lock() {
    static std::mutex lock;
    return lock;
}

std::string new_webhook_lease_id() {
    auto first = sx::webserver::HttpSessions::generate_auth_token();
    auto second = sx::webserver::HttpSessions::generate_auth_token();
    if(first.empty() or second.empty()) return {};
    return first + second;
}
}

static nlohmann::json wh_register(struct MHD_Connection * connection, std::string const& meth, std::string const& req) {

    using namespace jsonize;

    std::string new_url = load_json_params<std::string>(req, "rande_url").value_or("");
    bool rande_tls_verify = load_json_params<bool>(req, "rande_tls_verify").value_or(true);

    const char* response = "rejected";
    {
        auto control_lock = std::scoped_lock(webhook_control_lock());
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        auto fac = CfgFactory::get();

        if(fac->settings_webhook.enabled and fac->settings_webhook.allow_api_override
           and not new_url.empty()
           and not webhook_v2_lease().target(time(nullptr)).active) {

            fac->settings_webhook.override.timeout.set_expiry(time(nullptr) + 60);  // extend by next 60s
            fac->settings_webhook.override.url = new_url;
            fac->settings_webhook.override.tls_verify = rande_tls_verify;
            response = "accepted";
        }
    }

    return {{"status", response }};

}

static nlohmann::json wh_unregister(struct MHD_Connection * connection, std::string const& meth, std::string const& req) {

    using namespace jsonize;

    const char* response = "unknown";
    {
        auto control_lock = std::scoped_lock(webhook_control_lock());
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        auto fac = CfgFactory::get();

        // set back defaults
        if(fac->settings_webhook.enabled and fac->settings_webhook.allow_api_override
           and not webhook_v2_lease().target(time(nullptr)).active) {
            fac->settings_webhook.override.url = "";
            fac->settings_webhook.override.tls_verify = true;
            fac->settings_webhook.override.timeout.set_expiry(time(nullptr)-1); // set expired

            response = "unregistered";
        }
    }

    return {{"status", response }};

}

static sx::webserver::Http_JsonResponseParams wh_lease_v2(
        struct MHD_Connection*, std::string const&, std::string const& req) {
    using namespace jsonize;
    using Lease = sx::webserver::WebhookOverrideLease;

    sx::webserver::Http_JsonResponseParams response;
    const auto url = load_json_params<std::string>(req, "url").value_or("");
    const auto tls_verify = load_json_params<bool>(req, "tls_verify").value_or(true);
    const auto ttl = load_json_params<unsigned>(req, "ttl_seconds").value_or(60);
    const auto presented = load_json_params<std::string>(req, "lease_id").value_or("");
    const auto now = time(nullptr);

    auto control_lock = std::scoped_lock(webhook_control_lock());
    auto cfg_lock = std::scoped_lock(CfgFactory::lock());
    auto fac = CfgFactory::get();
    if(not fac->settings_webhook.enabled or not fac->settings_webhook.allow_api_override) {
        response.response_code = MHD_HTTP_FORBIDDEN;
        response.response = {{"error", "webhook API override disabled"}};
        return response;
    }

    auto result = webhook_v2_lease().acquire_or_renew(
        url, tls_verify, ttl, presented, new_webhook_lease_id(), now);
    if(result.outcome == Lease::Outcome::conflict) {
        response.response_code = MHD_HTTP_CONFLICT;
        response.response = {{"status", "conflict"}, {"expires_at", result.expires_at}};
        return response;
    }
    if(result.outcome == Lease::Outcome::invalid) {
        response.response_code = MHD_HTTP_BAD_REQUEST;
        response.response = {{"error", "invalid webhook lease request"}};
        return response;
    }

    fac->settings_webhook.override.url = url;
    fac->settings_webhook.override.tls_verify = tls_verify;
    fac->settings_webhook.override.timeout.set_expiry(result.expires_at);

    response.response_code = result.outcome == Lease::Outcome::acquired
        ? MHD_HTTP_CREATED : MHD_HTTP_OK;
    response.response = {{"status", result.outcome == Lease::Outcome::acquired ? "acquired" : "renewed"},
                         {"lease_id", result.lease_id}, {"expires_at", result.expires_at}};
    return response;
}

static sx::webserver::Http_JsonResponseParams wh_lease_release_v2(
        struct MHD_Connection*, std::string const&, std::string const& req) {
    using namespace jsonize;
    using Lease = sx::webserver::WebhookOverrideLease;
    sx::webserver::Http_JsonResponseParams response;
    const auto lease_id = load_json_params<std::string>(req, "lease_id").value_or("");
    const auto now = time(nullptr);

    auto control_lock = std::scoped_lock(webhook_control_lock());
    auto result = webhook_v2_lease().release(lease_id, now);
    if(result.outcome == Lease::Outcome::conflict) {
        response.response_code = MHD_HTTP_CONFLICT;
        response.response = {{"status", "conflict"}, {"expires_at", result.expires_at}};
        return response;
    }
    if(result.outcome == Lease::Outcome::absent) {
        response.response_code = MHD_HTTP_OK;
        response.response = {{"status", "already_released"}};
        return response;
    }
    {
        auto cfg_lock = std::scoped_lock(CfgFactory::lock());
        auto fac = CfgFactory::get();
        fac->settings_webhook.override.url.clear();
        fac->settings_webhook.override.tls_verify = true;
        fac->settings_webhook.override.timeout.set_expiry(now - 1);
    }
    response.response_code = MHD_HTTP_OK;
    response.response = {{"status", "released"}};
    return response;
}
