#include <service/http/webhook_control.hpp>
#include <proxy/connection_readiness.hpp>
#include <cassert>
#include <memory>

static void test_context_map_lookup() {

    sx::proxy::CxMap<int*, int> contexts;
    int left = 0;
    int right = 0;

    // Looking up an untracked CX must not create a lifecycle record.
    assert(contexts.find(&left) == nullptr);
    assert(contexts.begin() == contexts.end());

    contexts.get_or_create(&left) = 1;
    contexts.get_or_create(&right) = 2;
    assert(*contexts.find(&left) == 1);
    assert(*contexts.find(&right) == 2);

    const auto& observed = contexts;
    int total = 0;
    for(const auto& [cx, value] : observed) {
        total += value;
    }
    assert(total == 3);

    contexts.erase(&left);
    assert(contexts.find(&left) == nullptr);
    assert(*contexts.find(&right) == 2);
}

int main() {
    test_context_map_lookup();

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
