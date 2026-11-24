#pragma once

#include <service/httpd/httpd.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace sx::webserver {

struct AdministratorCreateRequest {
    std::string name;
    std::string password;
};

struct AdministratorPasswordRequest {
    std::string name;
    std::string password;
};

struct AdministratorEnabledRequest {
    std::string name;
    bool enabled {true};
};

struct AdministratorRemoveRequest {
    std::string name;
};

struct AdministratorEnrollmentRequest {
    std::string enrollment_token;
    std::string password;
};

template<class Request>
struct AdministratorRequestResult {
    std::optional<Request> request;
    std::string error;
};

AdministratorRequestResult<AdministratorCreateRequest>
parse_administrator_create_request(const nlohmann::json& document);
AdministratorRequestResult<AdministratorPasswordRequest>
parse_administrator_password_request(const nlohmann::json& document);
AdministratorRequestResult<AdministratorEnabledRequest>
parse_administrator_enabled_request(const nlohmann::json& document);
AdministratorRequestResult<AdministratorRemoveRequest>
parse_administrator_remove_request(const nlohmann::json& document);
AdministratorRequestResult<AdministratorEnrollmentRequest>
parse_administrator_enrollment_request(const nlohmann::json& document);

Http_JsonResponseParams administrator_collection(
    MHD_Connection* connection, const std::string& method, const std::string& request);
Http_JsonResponseParams administrator_password(
    MHD_Connection* connection, const std::string& method, const std::string& request);
Http_JsonResponseParams administrator_enabled(
    MHD_Connection* connection, const std::string& method, const std::string& request);
Http_JsonResponseParams administrator_enrollment(
    MHD_Connection* connection, const std::string& method, const std::string& request);

}  // namespace sx::webserver
