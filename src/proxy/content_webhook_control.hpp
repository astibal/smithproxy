#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace sx::proxy {

// Validate the complete callback-local connection-close reply. The deliberately
// narrow shape keeps termination separate from byte replacement and prevents a
// future response field from acquiring accidental close semantics.
inline std::optional<std::string> connection_close_reason(
        nlohmann::json const& reply) {
    if(!reply.is_object() || reply.size() != 3) return std::nullopt;

    auto const action = reply.find("action");
    auto const control = reply.find("control");
    auto const reason = reply.find("reason");
    if(action == reply.end() || !action->is_string() || *action != "close")
        return std::nullopt;
    if(control == reply.end() || !control->is_object() || control->size() != 1)
        return std::nullopt;
    auto const mode = control->find("mode");
    if(mode == control->end() || !mode->is_string() || *mode != "strict")
        return std::nullopt;
    if(reason == reply.end() || !reason->is_string()) return std::nullopt;

    auto value = reason->get<std::string>();
    if(value.empty() || value.size() > 1024) return std::nullopt;
    for(unsigned char character : value) {
        if(character < 0x20 || character == 0x7f) return std::nullopt;
    }
    return value;
}

} // namespace sx::proxy
