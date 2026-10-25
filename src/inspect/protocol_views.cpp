#include <inspect/protocol_views.hpp>

namespace sx::engine {
namespace {

// Protocol parsing remains complete on output, but host callbacks and DNS
// cache publication must not run a second time. Restore even if parsing throws.
class ObservationScope {
public:
    ObservationScope(EngineCtx& ctx, bool output)
        : ctx_(ctx), origin_(ctx.origin), only_(ctx.protocol_only) {
        if (output) {
            ctx_.origin = nullptr;
            ctx_.protocol_only = true;
        }
    }
    ~ObservationScope() {
        ctx_.origin = origin_;
        ctx_.protocol_only = only_;
    }
private:
    EngineCtx& ctx_;
    MitmHostCX* origin_;
    bool only_;
};

} // namespace

void ProtocolViews::observe(EngineCtx& ctx, Endpoint sender, buffer const& bytes,
                            std::uint64_t read_bytes, bool output) {
    if (bytes.empty()) return;

    ObservationScope scope(ctx, output);
    adapter(ctx).observe(ctx, sender == Endpoint::Client, bytes, read_bytes);
}

ProtocolAdapter const& ProtocolViews::adapter(EngineCtx const& ctx) {
    if (!adapter_) adapter_ = protocol_adapter(ctx);

    if (!adapter_) {
        throw std::logic_error("No endpoint-view adapter for protocol state");
    }

    return *adapter_;
}

bool ProtocolViews::prepare(Endpoint sender, buffer const& current,
                            duplexFlow const& history, bool ingested) {
    if (adapter_) return true;

    auto preparation = ProtocolAdapter::Preparation::Unavailable;
    adapter_ = prepare_protocol_adapter(context(sender), sender == Endpoint::Client,
                                        current, preparation);

    if (!adapter_) return false;
    if (preparation != ProtocolAdapter::Preparation::ReplayHistory) return true;

    // Detection can finish after earlier fragments. Replay retained input up
    // to, but excluding, this read. Only the adapter decides whether that old
    // history belongs to the newly selected protocol.
    auto const& blocks = history.flow_queue();

    for (std::size_t index = 0; index < blocks.size(); ++index) {
        auto const& block = blocks[index];
        auto length = block.data()->size();

        if (ingested && index + 1 == blocks.size()) {
            if (length < current.size()) {
                throw std::logic_error("Current read is missing from flow tail");
            }

            length -= current.size();
        }

        if (length) {
            seed(block.source() == 'r' ? Endpoint::Client : Endpoint::Server,
                 block.data()->view(0, length));
        }
    }

    return true;
}

std::uint64_t ProtocolViews::begin(Endpoint sender, buffer const& bytes,
                                  std::uint64_t read_bytes) {
    if (pending_) throw std::logic_error("Protocol callback is already active");

    auto& source = context(sender);
    Pending pending{++sequence_, sender, {}, nullptr};

    if (!split()) {
        // Preserve the PRE-input state, not a copy made after the webhook.
        // Current parser structures are mutable, not copy-on-write. This is
        // deliberately a deep copy until the first split; afterwards no copy
        // is needed. Unchanged output releases it without a second parse.
        pending.before = adapter(source).fork(source);
        pending.original = bytes.string_view();
    }

    pending_ = std::move(pending);
    observe(source, sender, bytes, read_bytes, false);
    return pending_->token;
}

void ProtocolViews::check_token(std::uint64_t token) const {
    if (!pending_ || pending_->token != token) {
        throw std::logic_error("Stale protocol callback token");
    }
}

void ProtocolViews::finish(std::uint64_t token, buffer const& bytes) {
    check_token(token);
    const auto sender = pending_->sender;

    if (!split() && pending_->original == bytes.string_view()) {
        pending_.reset();
        return;
    }

    if (!split()) {
        owner_ = sender;
        other_ = std::move(pending_->before);
    }

    // Empty output (need-more) still splits the views, but the receiver must
    // not advance until bytes are actually queued for it.
    observe(context(sender, Phase::Output), sender, bytes, 0, true);
    pending_.reset();
}

void ProtocolViews::abandon(std::uint64_t token) {
    check_token(token);
    // No output was delivered. Preserve that fact if the connection continues.
    buffer empty;
    finish(token, empty);
}

void ProtocolViews::seed(Endpoint sender, buffer const& bytes) {
    if (sequence_ != 0 || split()) {
        throw std::logic_error("Cannot seed an active protocol conversation");
    }
    observe(shared_, sender, bytes, 0, true);
}

} // namespace sx::engine
