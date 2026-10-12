#pragma once

#include <cstddef>

namespace sx::ssh::detail {

inline constexpr std::size_t maximum_channels_per_session = 4096;

inline bool channel_budget_available(std::size_t active,
                                     std::size_t retired,
                                     std::size_t queued,
                                     bool opening) noexcept {
    if (active > maximum_channels_per_session ||
        retired > maximum_channels_per_session - active)
        return false;
    const auto used = active + retired;
    if (queued > maximum_channels_per_session - used)
        return false;
    const auto total = used + queued;
    return total < maximum_channels_per_session &&
           (!opening || total + 1 < maximum_channels_per_session);
}

} // namespace sx::ssh::detail
