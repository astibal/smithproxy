#include <inspect/protocol_adapter.hpp>
#include <inspect/engine/http2_adapter.hpp>

namespace sx::engine {
namespace {

// Registration knows the available implementations, not their parsing rules.
const ProtocolAdapter* const adapters[] = {&http::v2::protocol_adapter()};

} // namespace

ProtocolAdapter const* protocol_adapter(EngineCtx const& ctx) {
    for (auto adapter : adapters) {
        if (adapter->owns(ctx)) return adapter;
    }

    return nullptr;
}

ProtocolAdapter const* prepare_protocol_adapter(
    EngineCtx& ctx, bool from_client, buffer const& current,
    ProtocolAdapter::Preparation& preparation) {
    for (auto adapter : adapters) {
        preparation = adapter->prepare(ctx, from_client, current);

        if (preparation != ProtocolAdapter::Preparation::Unavailable) return adapter;
    }

    preparation = ProtocolAdapter::Preparation::Unavailable;
    return nullptr;
}

} // namespace sx::engine
