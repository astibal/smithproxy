#include <service/http/webhook_control.hpp>
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
}
