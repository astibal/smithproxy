#pragma once

#include <cstddef>

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

constexpr std::size_t configured_utility_workers(std::size_t configured,
                                                 std::size_t automatic) noexcept {
    if constexpr (mem_constrained) {
        return utility_workers;
    }
    return configured == 0 ? automatic : configured;
}

void initialize_process() noexcept;

} // namespace sx::build_profile
