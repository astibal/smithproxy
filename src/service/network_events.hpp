#pragma once

#include <service/network_context.hpp>
#include <map>
#include <set>

namespace sx::net {

struct NetworkEvent {
    bool warning;
    std::string message;
};

namespace detail {

// Validity transitions explain when policy metadata becomes unusable or recovers.
// Repeated failed role resynchronizations must not generate one cache event per retry.
inline void append_network_state_events(const InterfaceSnapshot& previous,
                                        const InterfaceSnapshot& next,
                                        std::vector<NetworkEvent>& events) {
    if(previous.valid != next.valid) {
        events.push_back({!next.valid, next.valid ? "snapshot synchronized" : "snapshot invalidated"});
    }
    if(previous.roles_valid != next.roles_valid) {
        events.push_back({!next.roles_valid, next.roles_valid ? "interface roles available" : "interface roles unavailable"});
    }
    if(previous.route_generation != next.route_generation && next.valid &&
       (next.roles_valid || previous.roles_valid || !previous.valid)) {
        events.push_back({false, "routing state refreshed; route cache invalidated; route_generation=" +
            std::to_string(next.route_generation)});
    }
}

// Compare by ifindex, not vector position or name: a rename is a change to the
// same interface. Entries left in the old map are interfaces that disappeared.
inline void append_network_interface_events(const InterfaceSnapshot& previous,
                                            const InterfaceSnapshot& next,
                                            std::vector<NetworkEvent>& events) {
    std::map<std::uint32_t, InterfaceInfo> before;
    for(const auto& interface : previous.interfaces) {
        before.emplace(interface.index, interface);
    }
    for(const auto& interface : next.interfaces) {
        const auto found = before.find(interface.index);
        const auto label = "ifindex=" + std::to_string(interface.index) + " name=" + interface.name;
        if(found == before.end()) {
            events.push_back({false, "interface added: " + label + " role=" + interface.role +
                " flags=" + std::to_string(interface.flags)});
            continue;
        }
        const auto& old = found->second;
        if(old.name != interface.name || old.flags != interface.flags) {
            events.push_back({false, "interface changed: " + label + " previous_name=" + old.name +
                " flags=" + std::to_string(old.flags) + "->" + std::to_string(interface.flags)});
        }
        if(old.role != interface.role) {
            events.push_back({false, "interface role changed: " + label + " " + old.role + "->" +
                interface.role + " role_generation=" + std::to_string(next.role_generation)});
        }
        before.erase(found);
    }
    for(const auto& [index, interface] : before) {
        events.push_back({false, "interface removed: ifindex=" + std::to_string(index) + " name=" + interface.name});
    }
}

// Use a stable description to make set differences independent of dump ordering.
// Prefix, scope and flags are part of the address state, not just the IP itself.
inline std::set<std::string> network_address_descriptions(const InterfaceSnapshot& snapshot) {
    std::set<std::string> values;
    for(const auto& address : snapshot.addresses) {
        values.insert("ifindex=" + std::to_string(address.interface_index) + " " + address.text() +
            "/" + std::to_string(address.prefix_length) + " scope=" + std::to_string(address.scope) +
            " flags=" + std::to_string(address.flags));
    }
    return values;
}

// An address attribute change appears as removal of the old description followed
// by addition of the new one. This preserves both values in the event trail.
inline void append_network_address_events(const InterfaceSnapshot& previous,
                                          const InterfaceSnapshot& next,
                                          std::vector<NetworkEvent>& events) {
    const auto old_addresses = network_address_descriptions(previous);
    const auto new_addresses = network_address_descriptions(next);
    for(const auto& address : old_addresses) {
        if(!new_addresses.count(address)) {
            events.push_back({false, "address removed: " + address});
        }
    }
    for(const auto& address : new_addresses) {
        if(!old_addresses.count(address)) {
            events.push_back({false, "address added: " + address});
        }
    }
}

} // namespace detail

// Describe the difference between two published states, not raw netlink packets.
// This pure comparison also serves role-config reloads and is silent for equal
// snapshots. The caller publishes first, releases its lock, then delivers events.
inline std::vector<NetworkEvent> network_snapshot_events(
    const InterfaceSnapshot& previous, const InterfaceSnapshot& next) {
    std::vector<NetworkEvent> events;
    detail::append_network_state_events(previous, next, events);
    detail::append_network_interface_events(previous, next, events);
    detail::append_network_address_events(previous, next, events);
    return events;
}

} // namespace sx::net
