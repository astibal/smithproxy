#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace sx::webserver {

struct LoginRequest {
    LoginRequest(std::string username_value, std::string password_value);
    ~LoginRequest();
    LoginRequest(LoginRequest&&) noexcept = default;
    LoginRequest& operator=(LoginRequest&&) = delete;
    LoginRequest(const LoginRequest&) = delete;
    LoginRequest& operator=(const LoginRequest&) = delete;

    std::string username;
    std::string password;
};

struct LoginRequestResult {
    std::optional<LoginRequest> request;
    std::string error;
};

// Strictly decodes one application/x-www-form-urlencoded login request.
// Unknown, duplicate, missing or unsafe fields return an explanatory error;
// the returned request cleanses its password when destroyed.
LoginRequestResult parse_login_request(std::string_view body);

}  // namespace sx::webserver
