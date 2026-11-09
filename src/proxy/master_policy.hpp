#pragma once

#include <atomic>
#include <cstdint>

namespace sx::proxy {
// Shared by all master types. Configuration advances the generation after
// loading policies; workers will track their own last processed generation.
struct policy_state_t {
    static inline std::atomic<std::uint64_t> generation{0};
};
} // namespace sx::proxy
