#include <service/http/webhook_control.hpp>
#include <proxy/content_webhook_control.hpp>
#include <cassert>
#include <memory>

int main() {
    using sx::http::webhooks::webhook_control_t;
    auto control = std::make_shared<webhook_control_t>();
    webhook_control_t other_connection;
    assert(!control->strict());

    control->apply({{"control", {{"mode", "strict"}}}});
    assert(control->strict());
    assert(!other_connection.strict());

    for(auto const& input : {"null", "[]", "{}", "{\"control\":null}",
                            "{\"control\":{\"mode\":false}}",
                            "{\"control\":{\"mode\":\"future\"}}", "invalid"}) {
        control->apply(nlohmann::json::parse(input, nullptr, false));
        assert(control->strict());
    }

    // A late async response owns only policy state, not the destroyed proxy.
    auto callback_state = control;
    control.reset();
    callback_state->apply({{"control", {{"mode", "regular"}, {"future", true}}}});
    assert(!callback_state->strict());
    callback_state->apply({{"control", {{"mode", "strict"}}}, {"action", "accept"}});
    assert(callback_state->strict());

    const auto valid_close = nlohmann::json{
        {"action", "close"},
        {"control", {{"mode", "strict"}}},
        {"reason", "Connection killed."},
    };
    assert(sx::proxy::connection_close_reason(valid_close) == "Connection killed.");

    for(auto invalid : {
            nlohmann::json(nullptr),
            nlohmann::json::array(),
            nlohmann::json{{"action", "close"}},
            nlohmann::json{{"action", "drop"}, {"control", {{"mode", "strict"}}},
                           {"reason", "Connection killed."}},
            nlohmann::json{{"action", "close"}, {"control", {{"mode", "regular"}}},
                           {"reason", "Connection killed."}},
            nlohmann::json{{"action", "close"}, {"control", {{"mode", "strict"}}},
                           {"reason", ""}},
            nlohmann::json{{"action", "close"}, {"control", {{"mode", "strict"}}},
                           {"reason", "bad\nreason"}},
            nlohmann::json{{"action", "close"}, {"control", {{"mode", "strict"}}},
                           {"reason", "Connection killed."}, {"content", ""}},
        }) {
        assert(!sx::proxy::connection_close_reason(invalid));
    }

    auto oversized = valid_close;
    oversized["reason"] = std::string(1025, 'x');
    assert(!sx::proxy::connection_close_reason(oversized));
}
