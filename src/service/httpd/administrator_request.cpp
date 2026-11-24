#include "administrator_api.hpp"

#include <service/httpd/httpd.hpp>

#include <set>
#include <string_view>
#include <utility>

namespace sx::webserver {
namespace {

template<class Request>
AdministratorRequestResult<Request> invalid_request(std::string error) {
    return {std::nullopt, std::move(error)};
}

bool has_only_fields(
    const nlohmann::json& document, const std::set<std::string>& allowed) {
    if(!document.is_object()) return false;
    for(const auto& [name, value] : document.items()) {
        static_cast<void>(value);
        if(allowed.find(name) == allowed.end()) return false;
    }
    return true;
}

bool has_string(const nlohmann::json& document, std::string_view name) {
    const auto found = document.find(name);
    return found != document.end() && found->is_string();
}

}  // namespace

AdministratorRequestResult<AdministratorCreateRequest>
parse_administrator_create_request(const nlohmann::json& document) {
    const bool valid_fields = has_only_fields(
        document, {"name", "password", HttpSessions::ATT_AUTH_TOKEN,
                   HttpSessions::ATT_CSRF_TOKEN});
    if(!valid_fields || !has_string(document, "name") ||
       !has_string(document, "password")) {
        return invalid_request<AdministratorCreateRequest>(
            "request requires string name and password fields");
    }
    return {AdministratorCreateRequest{
        document["name"].get<std::string>(), document["password"].get<std::string>()}, {}};
}

AdministratorRequestResult<AdministratorPasswordRequest>
parse_administrator_password_request(const nlohmann::json& document) {
    const auto parsed = parse_administrator_create_request(document);
    if(!parsed.request)
        return invalid_request<AdministratorPasswordRequest>(parsed.error);
    return {AdministratorPasswordRequest{
        std::move(parsed.request->name), std::move(parsed.request->password)}, {}};
}

AdministratorRequestResult<AdministratorEnabledRequest>
parse_administrator_enabled_request(const nlohmann::json& document) {
    const bool valid_fields = has_only_fields(
        document, {"name", "enabled", HttpSessions::ATT_AUTH_TOKEN,
                   HttpSessions::ATT_CSRF_TOKEN});
    const auto enabled = document.find("enabled");
    if(!valid_fields || !has_string(document, "name") ||
       enabled == document.end() || !enabled->is_boolean()) {
        return invalid_request<AdministratorEnabledRequest>(
            "request requires string name and boolean enabled fields");
    }
    return {AdministratorEnabledRequest{
        document["name"].get<std::string>(), enabled->get<bool>()}, {}};
}

AdministratorRequestResult<AdministratorRemoveRequest>
parse_administrator_remove_request(const nlohmann::json& document) {
    const bool valid_fields = has_only_fields(
        document, {"name", HttpSessions::ATT_AUTH_TOKEN,
                   HttpSessions::ATT_CSRF_TOKEN});
    if(!valid_fields || !has_string(document, "name")) {
        return invalid_request<AdministratorRemoveRequest>(
            "request requires a string name field");
    }
    return {AdministratorRemoveRequest{document["name"].get<std::string>()}, {}};
}

AdministratorRequestResult<AdministratorEnrollmentRequest>
parse_administrator_enrollment_request(const nlohmann::json& document) {
    const bool valid_fields = has_only_fields(
        document, {"enrollment_token", "password", HttpSessions::ATT_AUTH_TOKEN,
                   HttpSessions::ATT_CSRF_TOKEN});
    if(!valid_fields || !has_string(document, "enrollment_token") ||
       !has_string(document, "password")) {
        return invalid_request<AdministratorEnrollmentRequest>(
            "request requires string enrollment_token and password fields");
    }
    return {AdministratorEnrollmentRequest{
        document["enrollment_token"].get<std::string>(),
        document["password"].get<std::string>()}, {}};
}

}  // namespace sx::webserver
