#include <nlohmann/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/util.hpp>
#include <service/http/jsonize.hpp>

#include <service/cfgapi/cfgapi.hpp>

static nlohmann::json wh_register(struct MHD_Connection * connection, std::string const& meth, std::string const& req) {

    using namespace jsonize;

    std::string new_url = load_json_params<std::string>(req, "rande_url").value_or("");
    bool rande_tls_verify = load_json_params<bool>(req, "rande_tls_verify").value_or(true);

    const char* response = "rejected";
    {
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        auto fac = CfgFactory::get();

        if(fac->settings_webhook.allow_api_override) {
            fac->settings_webhook.override.timeout.extend(60);  // extend by next 60s
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
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        auto fac = CfgFactory::get();

        // set back defaults
        if(fac->settings_webhook.allow_api_override) {
            fac->settings_webhook.override.url = "";
            fac->settings_webhook.cfg_tls_verify = true;
            fac->settings_webhook.override.timeout.set_expiry(time(nullptr)-1); // set expired

            response = "unregistered";
        }
    }

    return {{"status", response }};

}
