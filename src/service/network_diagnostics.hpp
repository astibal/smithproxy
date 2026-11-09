#pragma once

#include <service/network_context.hpp>
#include <nlohmann/json.hpp>
#include <ctime>

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

inline std::string network_generations_text(const InterfaceSnapshot& snapshot) {
    auto route_time = network_change_time(snapshot.route_changed_at);
    auto role_time = network_change_time(snapshot.role_changed_at);
    return "  network generations (current): route=" + std::to_string(snapshot.route_generation) +
        " changed=" + (route_time.empty() ? "unknown" : route_time) +
        "; role=" + std::to_string(snapshot.role_generation) +
        " changed=" + (role_time.empty() ? "unknown" : role_time);
}

} // namespace sx::net
