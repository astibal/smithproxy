#pragma once

#include <service/network_context.hpp>
#include <nlohmann/json.hpp>
#include <ctime>
#include <utility>

namespace sx::net {

// Zero means that no generation change has been observed yet.
inline std::string network_change_time(std::chrono::system_clock::time_point time) {
    if(time == std::chrono::system_clock::time_point{}) {
        return {};
    }
    const auto seconds = std::chrono::system_clock::to_time_t(time);
    std::tm utc{};
    if(!::gmtime_r(&seconds, &utc)) {
        return {};
    }
    char text[32]{};
    if(std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) {
        return {};
    }
    return text;
}

inline nlohmann::json network_generations_json(const InterfaceSnapshot& snapshot) {
    const auto route_time = network_change_time(snapshot.route_changed_at);
    const auto role_time = network_change_time(snapshot.role_changed_at);
    return {
        {"route_generation", snapshot.route_generation},
        {"role_generation", snapshot.role_generation},
        {"route_changed_at", route_time.empty() ? nlohmann::json(nullptr) : nlohmann::json(route_time)},
        {"role_changed_at", role_time.empty() ? nlohmann::json(nullptr) : nlohmann::json(role_time)},
    };
}

// CLI uses elapsed time; machine-readable diagnostics retain UTC timestamps.
inline std::string network_change_age(std::chrono::system_clock::time_point time,
                                      std::chrono::system_clock::time_point now) {
    if(time == std::chrono::system_clock::time_point{}) return "unknown";
    // A wall-clock correction must not produce a negative age.
    auto seconds = now > time
        ? std::chrono::duration_cast<std::chrono::seconds>(now - time).count() : 0;
    std::string result;
    for(const auto& [unit, suffix] : {std::pair{86400, "d"}, {3600, "h"}, {60, "m"}}) {
        if(seconds >= unit) {
            result += std::to_string(seconds / unit) + suffix + " ";
            seconds %= unit;
        }
    }
    return result + std::to_string(seconds) + "s ago";
}

inline std::string network_generations_text(const InterfaceSnapshot& snapshot,
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) {
    return "  network generations (current): route=" + std::to_string(snapshot.route_generation) +
        " changed=" + network_change_age(snapshot.route_changed_at, now) +
        "; role=" + std::to_string(snapshot.role_generation) +
        " changed=" + network_change_age(snapshot.role_changed_at, now);
}

} // namespace sx::net
