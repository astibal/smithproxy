#pragma once

#include <nlohmann/json.hpp>
#include <service/network_diagnostics.hpp>
#include <sys/socket.h>

namespace sx::net {

inline nlohmann::json interface_snapshot_json(const InterfaceSnapshot& snapshot) {
    using nlohmann::json;
    auto interfaces = json::array();
    for(const auto& interface : snapshot.interfaces) {
        auto addresses = json::array();
        for(const auto& address : snapshot.addresses) {
            if(address.interface_index != interface.index) {
                continue;
            }
            addresses.push_back({
                {"family", address.family == AF_INET ? "IPv4" :
                           address.family == AF_INET6 ? "IPv6" : "other"},
                {"address", address.text()},
                {"prefix_length", address.prefix_length},
                {"scope", address.scope},
                {"flags", address.flags},
            });
        }
        interfaces.push_back({
            {"ifindex", interface.index},
            {"name", interface.name},
            {"role", interface.role},
            {"flags", interface.flags},
            {"uplink", snapshot.uplinks.count(interface.index) != 0},
            {"addresses", std::move(addresses)},
        });
    }
    auto result = network_generations_json(snapshot);
    result.update({
        {"snapshot_valid", snapshot.valid},
        {"roles_valid", snapshot.roles_valid},
        {"generation", snapshot.generation},

        {"interfaces", std::move(interfaces)},
    });
    return result;
}

inline nlohmann::json network_interfaces_json() {
    const auto& context = NetworkCtx::instance();
    const auto snapshot = context.snapshot();
    // An invalid snapshot remains useful for diagnosis, but is explicitly marked.
    auto result = snapshot ? interface_snapshot_json(*snapshot) : nlohmann::json{
        {"snapshot_valid", false}, {"roles_valid", false},
        {"generation", 0}, {"route_generation", 0}, {"role_generation", 0},
        {"route_changed_at", nullptr}, {"role_changed_at", nullptr},
        {"interfaces", nlohmann::json::array()},
    };
    result["running"] = context.stats().running;
    result["last_error"] = context.last_error();
    return result;
}

} // namespace sx::net
