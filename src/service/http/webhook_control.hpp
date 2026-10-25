#pragma once

#include <atomic>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace sx::http::webhooks {

// Per-connection policy, shared with asynchronous replies without owning a proxy.
struct webhook_control_t {
    enum class mode_t { regular, strict };
    std::atomic<mode_t> mode{mode_t::regular};
    std::atomic<std::uint64_t> content_sequence{0};

    bool strict() const { return mode.load() == mode_t::strict; }

    void apply(nlohmann::json const& reply) {
        if(!reply.is_object()) return;
        auto control = reply.find("control");
        if(control == reply.end() || !control->is_object()) return;

        auto value = control->find("mode");
        if(value == control->end() || !value->is_string()) return;

        if(*value == "strict") mode.store(mode_t::strict);
        else if(*value == "regular") mode.store(mode_t::regular);
        // Missing/unknown options never silently downgrade an active policy.
    }
};

}
