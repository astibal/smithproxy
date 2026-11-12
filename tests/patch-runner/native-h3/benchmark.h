// Helpers shared by the pinned ngtcp2 benchmark endpoints.
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace h3_bench {

// Validate the deterministic payload without storing it or involving a script
// in the data path. memcmp permits the C runtime's optimized bulk comparison.
inline bool all_zero(std::span<const uint8_t> data) {
    static constexpr std::array<uint8_t, 4096> zeros{};
    while (!data.empty()) {
        const auto count = std::min(data.size(), zeros.size());
        if (std::memcmp(data.data(), zeros.data(), count) != 0) {
            return false;
        }
        data = data.subspan(count);
    }
    return true;
}

} // namespace h3_bench
