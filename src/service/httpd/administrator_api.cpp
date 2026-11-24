#include "administrator_api.hpp"

#include <service/cfgapi/cfgapi.hpp>
#include <service/httpd/admin_enrollment.hpp>
#include <service/httpd/handlers/handlers.hpp>

#include <exception>
#include <mutex>
#include <string_view>
#include <utility>

namespace sx::webserver {
namespace {

constexpr std::string_view revision_header = "X-Smithproxy-Expected-Revision";
constexpr std::string_view archive_hash_header = "X-Smithproxy-Archive-SHA256";

Http_JsonResponseParams error_response(
    std::string code, std::string detail, unsigned int status) {
    Http_JsonResponseParams response;
    response.response_code = status;
    response.content_type = "application/json";
    response.response = {
        {"state", "error"},
        {"error", {{"code", std::move(code)}, {"detail", std::move(detail)}}},
    };
    return response;
}

struct Preconditions {
    std::string revision;
    std::string archive_hash;
};

std::optional<Preconditions> preconditions(MHD_Connection* connection) {
    const auto* revision = MHD_lookup_connection_value(
        connection, MHD_HEADER_KIND, revision_header.data());
    const auto* archive_hash = MHD_lookup_connection_value(
        connection, MHD_HEADER_KIND, archive_hash_header.data());
    if(!revision || !*revision || !archive_hash || !*archive_hash)
        return std::nullopt;
    return Preconditions{revision, archive_hash};
}

Http_JsonResponseParams invalid_json_request(std::string detail) {
    return error_response("invalid_administrator_request", std::move(detail),
                          MHD_HTTP_BAD_REQUEST);
}

Http_JsonResponseParams mutation_response(
    const sx::admin::MutationResult& result, std::string_view success_state,
    std::string_view administrator) {
    if(result.ok()) {
        Http_JsonResponseParams response;
        response.response_code = MHD_HTTP_OK;
        response.content_type = "application/json";
        response.response = {
            {"state", success_state},
            {"administrator", administrator},
            {"revision", result.persistence.revision.current_id},
            {"content_hash", result.persistence.archive_hash},
            {"changed", result.changed},
            {"restart_required", CfgFactory::get()->startup_archive_pending()},
        };
        return response;
    }

    using Mutation = sx::admin::MutationStatus;
    using Persistence = sx::cfg::ResourceWriteStatus;
    std::string code;
    unsigned int status = MHD_HTTP_CONFLICT;
    switch(result.status) {
        case Mutation::invalid_name:
            code = "invalid_administrator_name";
            status = MHD_HTTP_UNPROCESSABLE_CONTENT;
            break;
        case Mutation::invalid_password:
            code = "invalid_administrator_password";
            status = MHD_HTTP_UNPROCESSABLE_CONTENT;
            break;
        case Mutation::already_exists: code = "administrator_exists"; break;
        case Mutation::not_found:
            code = "administrator_not_found";
            status = MHD_HTTP_NOT_FOUND;
            break;
        case Mutation::last_enabled_administrator:
            code = "final_enabled_administrator";
            break;
        case Mutation::persistence_error:
            switch(result.persistence.status) {
                case Persistence::invalid_resource:
                    code = "administrator_config_invalid";
                    status = MHD_HTTP_UNPROCESSABLE_CONTENT;
                    break;
                case Persistence::hash_mismatch: code = "archive_hash_mismatch"; break;
                case Persistence::lease_busy: code = "write_lease_busy"; break;
                case Persistence::stale_revision: code = "stale_revision"; break;
                case Persistence::unsaved_running: code = "unsaved_running_config"; break;
                case Persistence::native_unavailable:
                    code = "native_archive_unavailable";
                    break;
                case Persistence::write_failed:
                    code = "administrator_write_failed";
                    status = MHD_HTTP_INTERNAL_SERVER_ERROR;
                    break;
                case Persistence::written:
                    code = "administrator_write_failed";
                    status = MHD_HTTP_INTERNAL_SERVER_ERROR;
                    break;
            }
            break;
        case Mutation::written: break;
    }

    auto response = error_response(std::move(code), result.detail, status);
    response.response["revision"] = result.persistence.revision.current_id;
    response.response["content_hash"] = result.persistence.archive_hash;
    return response;
}

template<class Request, class Parser, class Mutation, class Success>
Http_JsonResponseParams mutate_administrator(
    MHD_Connection* connection, const std::string& request, Parser parser,
    Mutation mutation, Success success, std::string_view success_state) {
    const auto expected = preconditions(connection);
    if(!expected) {
        return error_response(
            "missing_administrator_precondition",
            "administrator changes require expected revision and archive SHA-256 headers",
            MHD_HTTP_BAD_REQUEST);
    }

    try {
        auto decoded = parser(nlohmann::json::parse(request));
        if(!decoded.request) return invalid_json_request(std::move(decoded.error));
        const auto result = mutation(*expected, *decoded.request);
        auto response = mutation_response(
            result, success_state, decoded.request->name);
        if(result.ok()) {
            const auto actor = authorized::current_actor();
            if(result.changed) success(*decoded.request);
            const auto action = std::string(success_state);
            Log::get()->events().insert(
                NOT, "administrator %s %s by %s via %s from %s changed=%s",
                decoded.request->name.c_str(), action.c_str(),
                actor.principal.c_str(), actor.authentication_method.c_str(),
                authorized::client_address(connection).c_str(),
                result.changed ? "true" : "false");
        }
        return response;
    }
    catch(const nlohmann::json::exception&) {
        return invalid_json_request("request body must be valid JSON");
    }
}

}  // namespace

Http_JsonResponseParams administrator_collection(
    MHD_Connection* connection, const std::string& method, const std::string& request) {
    if(method == "POST") {
        return mutate_administrator<AdministratorCreateRequest>(
            connection, request, parse_administrator_create_request,
            [](const Preconditions& expected, const AdministratorCreateRequest& decoded) {
                return CfgFactory::create_administrator(
                    expected.revision, expected.archive_hash, decoded.name, decoded.password);
            },
            [](const AdministratorCreateRequest& decoded) {
                HttpSessions::administrator_changed(decoded.name);
            },
            "created");
    }
    if(method == "DELETE") {
        return mutate_administrator<AdministratorRemoveRequest>(
            connection, request, parse_administrator_remove_request,
            [](const Preconditions& expected, const AdministratorRemoveRequest& decoded) {
                return CfgFactory::remove_administrator(
                    expected.revision, expected.archive_hash, decoded.name);
            },
            [](const AdministratorRemoveRequest& decoded) {
                HttpSessions::administrator_changed(decoded.name);
            },
            "removed");
    }

    try {
        const auto guard = std::scoped_lock(CfgFactory::lock());
        const auto config = CfgFactory::administrator_config();
        const auto revision = CfgFactory::board()->revision_state();
        const auto archive = CfgFactory::get()->archive_info();
        auto administrators = nlohmann::json::array();
        for(const auto& administrator : config.administrators()) {
            administrators.push_back({
                {"name", administrator.name}, {"enabled", administrator.enabled},
            });
        }

        Http_JsonResponseParams response;
        response.response_code = MHD_HTTP_OK;
        response.content_type = "application/json";
        response.response = {
            {"state", "ready"},
            {"revision", revision.current_id},
            {"content_hash", archive.content_hash},
            {"restart_required", CfgFactory::get()->startup_archive_pending()},
            {"administrators", std::move(administrators)},
        };
        return response;
    }
    catch(const std::exception& error) {
        return error_response("administrator_config_unavailable", error.what(),
                              MHD_HTTP_CONFLICT);
    }
}

Http_JsonResponseParams administrator_password(
    MHD_Connection* connection, const std::string&, const std::string& request) {
    return mutate_administrator<AdministratorPasswordRequest>(
        connection, request, parse_administrator_password_request,
        [](const Preconditions& expected, const AdministratorPasswordRequest& decoded) {
            return CfgFactory::change_administrator_password(
                expected.revision, expected.archive_hash, decoded.name, decoded.password);
        },
        [](const AdministratorPasswordRequest& decoded) {
            HttpSessions::administrator_changed(decoded.name);
        },
        "password_changed");
}

Http_JsonResponseParams administrator_enabled(
    MHD_Connection* connection, const std::string&, const std::string& request) {
    return mutate_administrator<AdministratorEnabledRequest>(
        connection, request, parse_administrator_enabled_request,
        [](const Preconditions& expected, const AdministratorEnabledRequest& decoded) {
            return CfgFactory::set_administrator_enabled(
                expected.revision, expected.archive_hash, decoded.name, decoded.enabled);
        },
        [](const AdministratorEnabledRequest& decoded) {
            HttpSessions::administrator_changed(decoded.name);
        },
        "enabled_changed");
}

Http_JsonResponseParams administrator_enrollment(
    MHD_Connection* connection, const std::string&, const std::string& request) {
    // The high-entropy, short-lived, single-use enrollment token is the
    // authorization capability for this endpoint. Requiring an existing
    // administrator session here would make first-administrator bootstrap
    // impossible. Every other administrator mutation remains session
    // protected at controller registration.
    const auto expected = preconditions(connection);
    if(!expected) {
        return error_response(
            "missing_administrator_precondition",
            "enrollment requires expected revision and archive SHA-256 headers",
            MHD_HTTP_BAD_REQUEST);
    }

    try {
        auto decoded = parse_administrator_enrollment_request(
            nlohmann::json::parse(request));
        if(!decoded.request) return invalid_json_request(std::move(decoded.error));

        auto claim = AdminEnrollmentStore::instance().claim(
            decoded.request->enrollment_token);
        if(!claim) {
            Log::get()->events().insert(
                WAR, "invalid, expired, or busy administrator enrollment attempt from %s",
                authorized::client_address(connection).c_str());
            return error_response(
                "invalid_enrollment_token", "enrollment token is invalid or unavailable",
                MHD_HTTP_FORBIDDEN);
        }

        const auto result = CfgFactory::create_administrator(
            expected->revision, expected->archive_hash, claim->administrator(),
            decoded.request->password);
        auto response = mutation_response(result, "enrolled", claim->administrator());
        if(!result.ok()) return response;

        const auto administrator = claim->administrator();
        HttpSessions::administrator_changed(administrator);
        const bool consumed = claim->commit();
        if(!consumed) {
            Log::get()->events().insert(
                WAR, "administrator %s persisted after its enrollment claim was cleared",
                administrator.c_str());
        }
        Log::get()->events().insert(
            NOT, "administrator %s enrolled via enrollment-token from %s",
            administrator.c_str(),
            authorized::client_address(connection).c_str());
        return response;
    }
    catch(const nlohmann::json::exception&) {
        return invalid_json_request("request body must be valid JSON");
    }
}

}  // namespace sx::webserver
