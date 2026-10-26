#include <inspect/protocol_views.hpp>

namespace sx::engine {
namespace {

// Protocol parsing remains complete on output, but host callbacks and DNS
// cache publication must not run a second time. Restore even if parsing throws.
class ObservationScope {
public:
    ObservationScope(EngineCtx& ctx, bool output, PayloadAnalysis* analysis)
        : ctx_(ctx), origin_(ctx.origin), only_(ctx.protocol_only),
          analysis_(ctx.payload_analysis) {
        ctx_.payload_analysis = analysis ? analysis : (output ? &protocol_only_ : nullptr);

        if (output) {
            ctx_.origin = nullptr;
            ctx_.protocol_only = true;
        }
    }
    ~ObservationScope() {
        ctx_.origin = origin_;
        ctx_.protocol_only = only_;
        ctx_.payload_analysis = analysis_;
    }
private:
    EngineCtx& ctx_;
    MitmHostCX* origin_;
    bool only_;
    PayloadAnalysis* analysis_;
    PayloadAnalysis protocol_only_ = PayloadAnalysis::protocol_only();
};

} // namespace

void ProtocolViews::set_mode(Mode mode) {
    if (mode == mode_) return;

    if (sequence_ || split()) {
        throw std::logic_error("Protocol mode must be selected before input analysis");
    }

    mode_ = mode;
}

void ProtocolViews::prepare_output() {
    if (mode_ != Mode::Rewrite || split()) return;

    // Clone once, before the first adapted input. Protocol discovery may have
    // replayed a retained prefix, but the current read is not in this state yet.
    // Immutable protocol tables remain shared by the adapter's fork operation.
    other_ = adapter(shared_).fork(shared_);
}

void ProtocolViews::observe(EngineCtx& ctx, Endpoint sender, buffer const& bytes,
                            std::uint64_t read_bytes, bool output, PayloadAnalysis* analysis) {
    if (bytes.empty()) return;

    ObservationScope scope(ctx, output, analysis);
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

    prepare_output();
    auto& source = context(sender);
    pending_.emplace(Pending{++sequence_, sender, PayloadAnalysis()});
    observe(source, sender, bytes, read_bytes, false, &pending_->analysis);
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

    if (mode_ == Mode::Observe) {
        // Mutation permission is enforced at the webhook boundary. This path
        // needs neither a copy nor a second parse nor a byte-by-byte comparison.
        pending_.reset();
        return;
    }

    // Rewrite prepared both views before input. Empty output (need-more)
    // must not advance the receiver until bytes are actually queued for it.
    // No webhook follows this pass. The observation scope supplies an explicit
    // protocol-only analysis request, not a cache miss requiring another hash.
    observe(context(sender, Phase::Output), sender, bytes, 0, true);
    pending_.reset();
}

void ProtocolViews::abandon(std::uint64_t token) {
    check_token(token);
    // No output was delivered. Preserve that fact if the connection continues.
    buffer empty;
    finish(token, empty);
}

void ProtocolViews::seed(Endpoint sender, buffer const& bytes, PayloadAnalysis* analysis) {
    if (sequence_ != 0 || split()) {
        throw std::logic_error("Cannot seed an active protocol conversation");
    }
    observe(shared_, sender, bytes, 0, true, analysis);
}

} // namespace sx::engine
