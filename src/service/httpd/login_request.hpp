#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace sx::webserver {

struct LoginRequest {
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
