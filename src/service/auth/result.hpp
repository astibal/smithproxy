#pragma once

#include <string>
#include <vector>

namespace sx::auth {

// Shared outcome of authentication, independent of the credential method
// and backend that verified it. Errors never grant access.
enum class Status {
    accepted,
    rejected,
    error,
};

struct Result {
    Status status = Status::error;
    std::string identity;
    std::string error;
    std::vector<std::string> groups{};

    explicit operator bool() const noexcept { return status == Status::accepted; }
};

} // namespace sx::auth
