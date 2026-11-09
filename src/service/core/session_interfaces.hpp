#pragma once

#include <nlohmann/json.hpp>
#include <service/network_diagnostics.hpp>

namespace sx::net {

// Indices belong to the flow; names and roles describe the current snapshot.
inline nlohmann::json session_interface_json(unsigned index, const InterfaceSnapshot* snapshot) {
    if(index == 0) {
        return nullptr;
    }

    nlohmann::json result = {{"ifindex", index}, {"name", nullptr}, {"role", nullptr}};
    if(snapshot && snapshot->valid) {
        if(const auto name = snapshot->interface_name(index)) {
            result["name"] = *name;
        }
        if(snapshot->roles_valid) {
            if(const auto role = snapshot->interface_role(index)) {
                result["role"] = *role;
            }
        }
    }
    return result;
}

inline nlohmann::json session_interfaces_json(unsigned ingress, unsigned egress) {
    const auto snapshot = NetworkCtx::instance().snapshot();
    return {
        {"ingress", session_interface_json(ingress, snapshot.get())},
        {"egress", session_interface_json(egress, snapshot.get())},
    };
}

inline std::string session_interface_text(unsigned index, const InterfaceSnapshot* snapshot) {
    if(index == 0) {
        return "unknown";
    }
    std::string name = "ifindex " + std::to_string(index);
    std::string role = "unknown";
    if(snapshot && snapshot->valid) {
        name = snapshot->interface_name(index).value_or(name);
        if(snapshot->roles_valid) {
            role = snapshot->interface_role(index).value_or(role);
        }
    }
    return name + " (" + role + ")";
}

inline std::string session_interfaces_text(unsigned ingress, unsigned egress) {
    const auto snapshot = NetworkCtx::instance().snapshot();
    return "  interfaces: " + session_interface_text(ingress, snapshot.get()) +
           " -> " + session_interface_text(egress, snapshot.get());
}

} // namespace sx::net
