#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace sx::admin {

enum class LoginStatus {
    accepted,
    rejected,
    throttled,
    unavailable,
};

struct LoginResult {
    LoginStatus status {LoginStatus::unavailable};
    std::string identity;
    std::string authentication_method;
    bool managed_administrator {false};
    std::int64_t retry_after_seconds {0};
};

// Applies the same managed-administrator precedence, PAM compatibility and
// online-attempt limits for every management transport.
LoginResult authenticate(
    std::string_view source,
    std::string_view username,
    std::string_view password);

} // namespace sx::admin
