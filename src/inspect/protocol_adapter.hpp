#ifndef SX_PROTOCOL_ADAPTER_HPP
#define SX_PROTOCOL_ADAPTER_HPP

#include <inspect/engine.hpp>

namespace sx::engine {

// Protocol-owned operations. Endpoint routing and callback transactions do not
// need to know the protocol's detection rules, parser or mutable state layout.
class ProtocolAdapter {
public:
    enum class Preparation { Unavailable, Ready, ReplayHistory };

    virtual ~ProtocolAdapter() = default;
    virtual bool owns(EngineCtx const& ctx) const = 0;
    virtual Preparation prepare(EngineCtx& ctx, bool from_client,
                                buffer const& current) const = 0;
    virtual void observe(EngineCtx& ctx, bool from_client, buffer const& bytes,
                         std::uint64_t read_bytes) const = 0;
    virtual std::unique_ptr<EngineCtx> fork(EngineCtx const& ctx) const = 0;
};

// Registered adapters have process lifetime. A null result means the engine
// keeps its existing raw-flow path; it does not imply an invalid protocol.
ProtocolAdapter const* protocol_adapter(EngineCtx const& ctx);
ProtocolAdapter const* prepare_protocol_adapter(
    EngineCtx& ctx, bool from_client, buffer const& current,
    ProtocolAdapter::Preparation& preparation);

// Compatibility path for engines not yet supporting endpoint views.
void observe_unadapted_content(EngineCtx& ctx, bool from_client,
                               buffer const& bytes, std::uint64_t read_bytes);

} // namespace sx::engine
#endif
