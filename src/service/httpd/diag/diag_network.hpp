#pragma once

#include <nlohmann/json.hpp>
#include <service/network_diagnostics.hpp>
#include <sys/socket.h>

#include <chrono>

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
    const auto stats = context.stats();
    const auto last_error = context.last_error();
    // An invalid snapshot remains useful for diagnosis, but is explicitly marked.
    auto result = snapshot ? interface_snapshot_json(*snapshot) : nlohmann::json{
        {"snapshot_valid", false}, {"roles_valid", false},
        {"generation", 0}, {"route_generation", 0}, {"role_generation", 0},
        {"route_changed_at", nullptr}, {"role_changed_at", nullptr},
        {"interfaces", nlohmann::json::array()},
    };
    std::uint64_t ipv4_addresses = 0;
    std::uint64_t ipv6_addresses = 0;
    if(snapshot) {
        for(const auto& address : snapshot->addresses) {
            ipv4_addresses += address.family == AF_INET;
            ipv6_addresses += address.family == AF_INET6;
        }
    }

    const bool ready = stats.running && snapshot && snapshot->valid && snapshot->roles_valid;
    const auto state = ready ? "ready" :
        stats.running && stats.synchronization_attempts == 0 ? "starting" :
        snapshot || stats.errors != 0 ? "degraded" : "unavailable";
    const auto sampled_at = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Keep the detailed diagnostic payload and add a stable summary contract for
    // management clients. Raw kernel details never need to leave the GUI backend.
    result.update({
        {"schema_version", 1},
        {"state", state},
        {"sampled_at_unix_ms", sampled_at},
        {"synchronization", {
            {"running", stats.running},
            {"attempts", stats.synchronization_attempts},
            {"successes", stats.synchronization_successes},
            {"errors", stats.errors},
            {"event_datagrams", stats.event_datagrams},
            {"changed_event_datagrams", stats.changed_event_datagrams},
        }},
        {"totals", {
            {"interfaces", snapshot ? snapshot->interfaces.size() : 0},
            {"addresses", snapshot ? snapshot->addresses.size() : 0},
            {"ipv4_addresses", ipv4_addresses},
            {"ipv6_addresses", ipv6_addresses},
        }},
        {"running", stats.running},
        {"last_error", last_error},
        {"last_error_code", last_error.empty() ? nlohmann::json(nullptr) :
                                                  nlohmann::json("network-context-error")},
    });
    return result;
}

} // namespace sx::net
