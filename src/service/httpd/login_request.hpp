#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace sx::webserver {

struct LoginRequest {
    LoginRequest(std::string username_value, std::string password_value);
    ~LoginRequest();
    LoginRequest(LoginRequest&&) noexcept = default;
    LoginRequest& operator=(LoginRequest&&) noexcept = default;
    LoginRequest(const LoginRequest&) = delete;
    LoginRequest& operator=(const LoginRequest&) = delete;

    std::string username;
    std::string password;
};

struct LoginRequestResult {
    std::optional<LoginRequest> request;
    std::string error;
};

// Strictly decode one application/x-www-form-urlencoded login request.
LoginRequestResult parse_login_request(std::string_view body);

}  // namespace sx::webserver
