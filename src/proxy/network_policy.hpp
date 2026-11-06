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
    if(!ingress && !egress) return true;
    if(!snapshot.valid || !snapshot.roles_valid) return false;
    if(ingress) for(auto* cx : left) {
        if(!cx || !cx->com() || !snapshot.interface_role(cx->com()->ingress_ifindex())) return false;
    }
    if(egress) for(auto* cx : right) {
        if(!cx || !cx->com()) return false;
        const auto index = sx::net::NetworkCtx::instance().route_lookup(cx->host());
        cx->com()->egress_ifindex(index.value_or(0));
        if(!index || !snapshot.interface_role(*index)) return false;
    }
    return true;
}
}
