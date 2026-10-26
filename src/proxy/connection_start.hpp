#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>

namespace sx::proxy {

enum class setup_action { accept, drop, not_interested, invalid };

struct setup_reply {
    setup_action action = setup_action::invalid;
    nlohmann::json body;
    bool rewrite = false;
};

// Parse only the setup decision, not content actions. In particular, discard
// must never accidentally become a connection drop. Old successful receivers
// often return no action (or no body), which remains an acceptance.
inline setup_reply parse_setup_reply(long status, std::string_view body) {
    if (status < 200 || status >= 300) return {};

    if (body.find_first_not_of(" \t\r\n") == std::string_view::npos)
        return {setup_action::accept, nlohmann::json::object()};

    auto parsed = nlohmann::json::parse(body.begin(), body.end(), nullptr, false);

    if (!parsed.is_object()) return {};

    bool rewrite = false;
    const auto control = parsed.find("control");

    if (control != parsed.end()) {
        if (!control->is_object()) return {setup_action::invalid, std::move(parsed)};

        const auto permission = control->find("rewrite");

        if (permission != control->end()) {
            if (!permission->is_boolean()) return {setup_action::invalid, std::move(parsed)};
            rewrite = permission->get<bool>();
        }
    }

    const auto action = parsed.find("action");

    if (action == parsed.end()) return {setup_action::accept, std::move(parsed), rewrite};
    if (!action->is_string()) return {setup_action::invalid, std::move(parsed)};

    const auto& value = action->get_ref<const std::string&>();
    auto decision = setup_action::invalid;

    if (value == "accept" || value == "unchanged") decision = setup_action::accept;
    else if (value == "drop") decision = setup_action::drop;
    else if (value == "not-interested") decision = setup_action::not_interested;

    return {decision, std::move(parsed), decision == setup_action::accept && rewrite};
}

} // namespace sx::proxy
