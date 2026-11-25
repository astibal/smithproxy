#pragma once

#include <service/httpd/httpd.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace sx::webserver {

struct AdministratorCreateRequest {
    std::string name;
    std::string password;

    AdministratorCreateRequest(std::string name, std::string password);
    ~AdministratorCreateRequest();
    AdministratorCreateRequest(AdministratorCreateRequest&&) noexcept = default;
    AdministratorCreateRequest& operator=(AdministratorCreateRequest&&) = delete;
    AdministratorCreateRequest(const AdministratorCreateRequest&) = delete;
    AdministratorCreateRequest& operator=(const AdministratorCreateRequest&) = delete;
};

struct AdministratorPasswordRequest {
    std::string name;
    std::string password;

    AdministratorPasswordRequest(std::string name, std::string password);
    ~AdministratorPasswordRequest();
    AdministratorPasswordRequest(AdministratorPasswordRequest&&) noexcept = default;
    AdministratorPasswordRequest& operator=(AdministratorPasswordRequest&&) = delete;
    AdministratorPasswordRequest(const AdministratorPasswordRequest&) = delete;
    AdministratorPasswordRequest& operator=(const AdministratorPasswordRequest&) = delete;
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

    AdministratorEnrollmentRequest(std::string enrollment_token, std::string password);
    ~AdministratorEnrollmentRequest();
    AdministratorEnrollmentRequest(AdministratorEnrollmentRequest&&) noexcept = default;
    AdministratorEnrollmentRequest& operator=(AdministratorEnrollmentRequest&&) = delete;
    AdministratorEnrollmentRequest(const AdministratorEnrollmentRequest&) = delete;
    AdministratorEnrollmentRequest& operator=(const AdministratorEnrollmentRequest&) = delete;
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
