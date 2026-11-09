#pragma once

#include <cstdint>

namespace sx::proxy {
struct revalidation_result_t {
    std::uint64_t allowed = 0, terminated = 0, deferred = 0;
    std::uint64_t superseded = 0;

    bool complete() const { return deferred == 0 && superseded == 0; }
    bool empty() const { return allowed + terminated + deferred + superseded == 0; }

    // Report the first pending pass, actual terminations and final recovery.
    // Silent retries still run normally; they must not flood the event trail.
    bool report(bool first_pass) const {
        return !empty() && (first_pass || complete() || terminated != 0);
    }
};

} // namespace sx::proxy
