#include "save.hpp"

#include <utility>

#ifndef SX_CFG_TRANSACTION_CODEC_ONLY
 #include <service/httpd/mhd_compat.hpp>

 #include <service/cfgapi/cfg_save.hpp>
 #include <service/cfgapi/cfgapi.hpp>
 #include <service/httpd/handlers/handlers.hpp>
 #include <service/httpd/httpd.hpp>
#endif

namespace sx::webserver::cfg_save_api {
namespace {

namespace tx = sx::cfg::tx;

tx::Issue issue(std::string code, std::string detail) {
    return tx::Issue {
        tx::Issue::no_operation,
        std::move(code),
        {},
        std::move(detail),
    };
}

}  // namespace

sx::cfg::tx::Result<Request> decode_request(nlohmann::json const& body) {
    if(!body.is_object()) {
        return issue("invalid_request", "Request body must be an object");
    }
    auto params = body.find("params");
    if(params == body.end() || !params->is_object()) {
        return issue("invalid_request", "Request requires a params object");
    }
    auto expected = params->find("expected_revision");
    if(expected == params->end()) {
        return issue("missing_expected_revision", "Request requires expected_revision");
    }
    if(!expected->is_string()) {
        return issue("invalid_expected_revision", "expected_revision must be a string");
    }
    auto revision = expected->get<std::string>();
    if(revision.empty() || revision.size() > 128) {
        return issue(
            "invalid_expected_revision",
            "expected_revision must contain between 1 and 128 characters");
    }
    return Request {std::move(revision)};
}

}  // namespace sx::webserver::cfg_save_api

#ifndef SX_CFG_TRANSACTION_CODEC_ONLY
namespace sx::webserver {
namespace {

Http_JsonResponseParams save_response(
    nlohmann::json body,
    unsigned int status = MHD_HTTP_OK) {
    Http_JsonResponseParams result;
    result.response_code = status;
    result.response = std::move(body);
    return result;
}

Http_JsonResponseParams save_error(
    std::string code,
    std::string detail,
    unsigned int status) {
    return save_response({
        {"state", "error"},
        {"error", {{"code", std::move(code)}, {"detail", std::move(detail)}}},
    }, status);
}

}  // namespace

Http_JsonResponseParams cfg_save(
    MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    std::string const& request) {
    nlohmann::json body;
    try {
        body = nlohmann::json::parse(request);
    }
    catch(nlohmann::json::exception const&) {
        return save_error(
            "invalid_json", "Request body is not valid JSON", MHD_HTTP_UNPROCESSABLE_CONTENT);
    }

    auto decoded = cfg_save_api::decode_request(body);
    if(!decoded) {
        return save_error(
            decoded.error().code,
            decoded.error().detail,
            MHD_HTTP_UNPROCESSABLE_CONTENT);
    }

    const std::string source = "api:" + authorized::client_address(connection);
    auto const saved = CfgFactory::save_running(decoded->expected_revision, source);

    using sx::cfg::SaveStatus;
    switch(saved.status) {
        case SaveStatus::lease_busy:
            return save_error(
                "lease_busy",
                "Configuration is locked by an active commit lease",
                MHD_HTTP_CONFLICT);
        case SaveStatus::stale_revision:
            return save_error(
                "stale_revision",
                "Running configuration changed before it could be saved",
                MHD_HTTP_CONFLICT);
        case SaveStatus::partial_config:
            return save_error(
                "partial_config",
                "Running configuration was loaded with errors and cannot be saved through the API",
                MHD_HTTP_UNPROCESSABLE_CONTENT);
        case SaveStatus::save_failed:
            return save_error(
                "save_failed",
                "Running configuration could not be written to the startup file",
                MHD_HTTP_INTERNAL_SERVER_ERROR);
        case SaveStatus::saved:
        case SaveStatus::unchanged:
            break;
    }

    return save_response({
        {"state", "saved"},
        {"revision", saved.revision.current_id},
        {"saved_revision", saved.revision.saved_id},
        {"unsaved", saved.revision.unsaved},
        {"changed", saved.changed()},
    });
}

}  // namespace sx::webserver
#endif
