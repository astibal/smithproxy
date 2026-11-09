#pragma once

#include <service/network_context.hpp>
#include <policy/policy.hpp>

namespace sx::proxy {
// Prepare once per policy selection, including explicit proxy vector matching.
// Missing required metadata stops selection instead of bypassing a deny rule.
inline bool prepare_network_policy(const std::vector<std::shared_ptr<PolicyRule>>& rules,
                                  const std::vector<baseHostCX*>& left,
                                  const std::vector<baseHostCX*>& right,
                                  const sx::net::InterfaceSnapshot& snapshot) {
    bool ingress = false, egress = false;
    for(const auto& rule : rules) {
        if(rule && !rule->is_disabled) {
            ingress |= !rule->ingress_role.empty();
            egress |= !rule->egress_role.empty();
        }
    }
    bool routes_known = true;
    for(auto* cx : right) {
        if(!cx || !cx->com()) {
            routes_known = false;
            continue;
        }
        const auto index = sx::net::NetworkCtx::instance().route_lookup(cx->host(), snapshot.route_generation);
        cx->com()->egress_ifindex(index.value_or(0));
        routes_known &= index.has_value() && snapshot.interface_role(*index).has_value();
    }
    if(!ingress && !egress) {
        return true;
    }
    if(!snapshot.valid || !snapshot.roles_valid) {
        return false;
    }
    if(ingress) {
        for(auto* cx : left) {
            if(!cx || !cx->com() || !snapshot.interface_role(cx->com()->ingress_ifindex())) {
                return false;
            }
        }
    }
    return !egress || routes_known;
}
}
