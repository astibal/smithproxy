#ifndef SX_PROTOCOL_VIEWS_HPP
#define SX_PROTOCOL_VIEWS_HPP

#include <inspect/protocol_adapter.hpp>

namespace sx::engine {

// Two endpoint-local, bidirectional conversations; NOT one parser per direction.
// Initially both selectors return the same engine. The first different output
// promotes a pre-input fork to the receiver's view. Later messages advance both
// views, without rollback or re-running the webhook. H2 is the first adapter.
class ProtocolViews {
public:
    enum class Endpoint { Client, Server };
    enum class Phase { Input, Output };

    ProtocolViews() = default;
    // An explicitly supplied adapter must outlive these views.
    explicit ProtocolViews(ProtocolAdapter const& adapter) : adapter_(&adapter) {}

    bool prepare(Endpoint sender, buffer const& current,
                 duplexFlow const& history, bool ingested);

    EngineCtx& context(Endpoint sender, Phase phase = Phase::Input) {
        const auto endpoint = phase == Phase::Input ? sender : peer(sender);
        return other_ && endpoint != owner_ ? *other_ : shared_;
    }
    EngineCtx const& context(Endpoint sender, Phase phase = Phase::Input) const {
        const auto endpoint = phase == Phase::Input ? sender : peer(sender);
        return other_ && endpoint != owner_ ? *other_ : shared_;
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
    void seed(Endpoint sender, buffer const& bytes);

private:
    struct Pending {
        std::uint64_t token;
        Endpoint sender;
        std::string original;
        std::unique_ptr<EngineCtx> before;
    };

    static Endpoint peer(Endpoint endpoint) {
        return endpoint == Endpoint::Client ? Endpoint::Server : Endpoint::Client;
    }
    void observe(EngineCtx& ctx, Endpoint sender, buffer const& bytes,
                        std::uint64_t read_bytes, bool output);
    ProtocolAdapter const& adapter(EngineCtx const& ctx);
    void check_token(std::uint64_t token) const;

    EngineCtx shared_;
    ProtocolAdapter const* adapter_ = nullptr;
    Endpoint owner_ = Endpoint::Client;
    std::unique_ptr<EngineCtx> other_;
    std::optional<Pending> pending_;
    std::uint64_t sequence_ = 0;
};

} // namespace sx::engine
#endif
