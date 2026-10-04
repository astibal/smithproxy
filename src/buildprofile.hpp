#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace sx::build_profile {

#ifdef MEM_CONSTRAINED
inline constexpr bool mem_constrained = true;
#else
inline constexpr bool mem_constrained = false;
#endif

// Constrained executables deliberately ignore configuration attempts to grow
// the helper pool. Protocol listener counts remain profile-specific.
inline constexpr std::size_t utility_workers = mem_constrained ? 5U : 0U;
inline constexpr bool cli_enabled = !mem_constrained;
inline constexpr bool heap_trim_enabled = mem_constrained;
inline constexpr auto heap_trim_quiet_period = std::chrono::seconds{10};
inline constexpr auto heap_trim_interval = std::chrono::seconds{60};

constexpr std::size_t configured_utility_workers(std::size_t configured,
                                                 std::size_t automatic) noexcept {
    if constexpr (mem_constrained) {
        return utility_workers;
    }
    return configured == 0 ? automatic : configured;
}

class heap_trim_schedule {
public:
    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;

    explicit heap_trim_schedule(std::uint64_t started_sessions,
                                time_point now = clock::now()) noexcept
        : observed_sessions_(started_sessions), observed_at_(now), last_trim_(now) {}

    bool observe(std::uint64_t started_sessions, time_point now = clock::now()) noexcept {
        if constexpr (!heap_trim_enabled) {
            return false;
        }
        if (now - observed_at_ < heap_trim_quiet_period) {
            return false;
        }

        const bool quiet = started_sessions == observed_sessions_;
        observed_sessions_ = started_sessions;
        observed_at_ = now;

        if (!quiet || now - last_trim_ < heap_trim_interval) {
            return false;
        }
        last_trim_ = now;
        return true;
    }

private:
    std::uint64_t observed_sessions_;
    time_point observed_at_;
    time_point last_trim_;
};

void initialize_process() noexcept;
bool trim_heap() noexcept;

} // namespace sx::build_profile
