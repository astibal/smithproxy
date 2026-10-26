#ifndef SX_PROTOCOL_VIEWS_HPP
#define SX_PROTOCOL_VIEWS_HPP

#include <inspect/protocol_adapter.hpp>

namespace sx::engine {

// Two endpoint-local, bidirectional conversations; NOT one parser per direction.
// Setup chooses one observation context or two rewrite-capable contexts. The
// decision precedes input analysis; no speculative per-payload copy is needed.
// Output advances protocol state only, without inspectors or another webhook.
class ProtocolViews {
public:
    enum class Endpoint { Client, Server };
    enum class Phase { Input, Output };
    enum class Mode { Observe, Rewrite };

    ProtocolViews() = default;
    explicit ProtocolViews(Mode mode) : mode_(mode) {}
    // An explicitly supplied adapter must outlive these views.
    explicit ProtocolViews(ProtocolAdapter const& adapter, Mode mode = Mode::Observe)
        : adapter_(&adapter), mode_(mode) {}

    void set_mode(Mode mode);

    bool prepare(Endpoint sender, buffer const& current,
                 duplexFlow const& history, bool ingested);

    EngineCtx& context(Endpoint sender, Phase phase = Phase::Input) {
        const auto endpoint = phase == Phase::Input ? sender : peer(sender);
        return other_ && endpoint == Endpoint::Server ? *other_ : shared_;
    }
    EngineCtx const& context(Endpoint sender, Phase phase = Phase::Input) const {
        const auto endpoint = phase == Phase::Input ? sender : peer(sender);
        return other_ && endpoint == Endpoint::Server ? *other_ : shared_;
    }
    bool split() const { return other_ != nullptr; }
    bool active() const { return adapter_ != nullptr; }

    // Exactly one input/finish pair may be outstanding. Tokens prevent an old
    // transaction from completing a newer callback accidentally.
    std::uint64_t begin(Endpoint sender, buffer const& bytes, std::uint64_t read_bytes);
    void finish(std::uint64_t token, buffer const& bytes);
    void abandon(std::uint64_t token);

    // Bootstrap retained pre-detection bytes, without external inspector effects.
    // Caller uses this only before the first begin(), never to replay a callback.
    // No publication identity is needed by default. Explicit analysis requests
    // allow diagnostic callers to compare publication work on identical data.
    void seed(Endpoint sender, buffer const& bytes, PayloadAnalysis* analysis = nullptr);

private:
    struct Pending {
        std::uint64_t token;
        Endpoint sender;
        PayloadAnalysis analysis;
    };

    static Endpoint peer(Endpoint endpoint) {
        return endpoint == Endpoint::Client ? Endpoint::Server : Endpoint::Client;
    }
    void observe(EngineCtx& ctx, Endpoint sender, buffer const& bytes,
                 std::uint64_t read_bytes, bool output, PayloadAnalysis* analysis = nullptr);
    ProtocolAdapter const& adapter(EngineCtx const& ctx);
    void check_token(std::uint64_t token) const;
    void prepare_output();

    EngineCtx shared_;
    ProtocolAdapter const* adapter_ = nullptr;
    std::unique_ptr<EngineCtx> other_;
    std::optional<Pending> pending_;
    std::uint64_t sequence_ = 0;
    Mode mode_ = Mode::Observe;
};

} // namespace sx::engine
#endif
