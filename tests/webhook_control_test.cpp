#include <service/http/webhook_control.hpp>
#include <proxy/connection_readiness.hpp>
#include <cassert>
#include <memory>

int main() {
    // STARTTLS must preserve TCP identity while permitting a new readiness
    // event; a replacement socket must get a distinct attempt identity.
    std::uint64_t sequence = 0;
    sx::proxy::ConnectionReadiness observed;
    int tcp = 0, tls = 0;
    observed.observe_context(10, &tcp, sequence);
    observed.connected = observed.ready = true;
    const auto attempt = observed.attempt;
    observed.observe_context(10, &tls, sequence);
    assert(observed.connected && !observed.ready && observed.attempt == attempt);
    observed.observe_context(11, &tls, sequence);
    assert(!observed.connected && !observed.ready && observed.attempt != attempt);

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
