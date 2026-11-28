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

// Authenticates one management login from the supplied transport source.
// Managed administrators take precedence; PAM is considered only when the
// managed store is not configured. The result also carries throttle timing
// and the identity metadata needed to create a management session.
LoginResult authenticate(
    std::string_view source,
    std::string_view username,
    std::string_view password);

} // namespace sx::admin
