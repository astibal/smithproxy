#pragma once

#include <atomic>
#include <cstdint>
#include <service/network_context.hpp>

namespace sx::proxy {
struct policy_state_t {
    // Configuration publishes this counter; workers never consume/reset it.
    static inline std::atomic<std::uint64_t> generation{0};

    struct generations_t {
        std::uint64_t policy, route, role;
        bool operator==(const generations_t& other) const {
            return policy == other.policy && route == other.route && role == other.role;
        }
    };

    static generations_t current_generations() {
        const auto network = sx::net::NetworkCtx::instance().snapshot();
        return {generation.load(std::memory_order_acquire),
                network->route_generation, network->role_generation};
    }

    // Capture the baseline at master creation, before it accepts sessions.
    generations_t observed = current_generations();
    bool revalidation_required = false;

    bool validate() { return validate(current_generations()); }

    // Generation comparison only, not a policy decision. A repeated check
    // cannot clear pending work; only completed revalidation may do that.
    bool validate(const generations_t& current) {
        if(!(current == observed)) {
            observed = current;
            revalidation_required = true;
        }
        return !revalidation_required;
    }
};
} // namespace sx::proxy
