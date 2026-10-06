#pragma once

#include <cstdint>
#include <ctime>

namespace sx::objapi {

inline bool day_is_within_age(time_t now_days, time_t seen_days,
                              unsigned int max_age_days) {
    if (seen_days >= now_days) return true;
    return static_cast<std::uintmax_t>(now_days - seen_days) <= max_age_days;
}

} // namespace sx::objapi
