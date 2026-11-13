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

bool ProtocolViews::enable_rewrite() {
    if (mode_ == Mode::Rewrite) return true;
    if (untracked_rewrite_) return false;
    if (pending_) throw std::logic_error("Cannot split an active protocol callback");

    // Before the first input the normal lazy fork suffices. Later admission of
    // a stream can request a fork of the exact state reached by earlier streams.
    if (sequence_) {
        try {
            auto copy = adapter(shared_).fork(shared_);
            other_ = std::move(copy);
        } catch (std::runtime_error const& error) {
            fork_error_ = error.what();
            return false;
        }
    }

    fork_error_.clear();
    mode_ = Mode::Rewrite;
    return true;
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
    observe(ctx, ProtocolInput{sender, bytes}, read_bytes, output, analysis);
}

void ProtocolViews::observe(EngineCtx& ctx, ProtocolInput const& input,
                            std::uint64_t read_bytes, bool output, PayloadAnalysis* analysis) {
    if (input.event == ProtocolEvent::Data && input.bytes.empty()) return;

    ObservationScope scope(ctx, output, analysis);
    adapter(ctx).observe(ctx, input, read_bytes);
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
    return begin(ProtocolInput{sender, bytes}, read_bytes);
}

std::uint64_t ProtocolViews::begin(ProtocolInput const& input, std::uint64_t read_bytes) {
    if (pending_) throw std::logic_error("Protocol callback is already active");

    prepare_output();
    auto& source = context(input.sender);
    pending_.emplace(Pending{++sequence_, input.sender, PayloadAnalysis(), input.stream, std::nullopt});
    // Unexpected raw overrides remain legal. Remember the original multiplexed
    // bytes only while shared so a divergence can be reported without claiming
    // that a later fork represents both endpoints. TCP/H2 keeps its fast path.
    if (input.stream && mode_ == Mode::Observe && input.event == ProtocolEvent::Data) {
        pending_->original = std::string(input.bytes.string_view());
    }
    try {
        observe(source, input, read_bytes, false, &pending_->analysis);
    } catch (...) {
        pending_.reset();
        throw;
    }
    return pending_->token;
}

void ProtocolViews::check_token(std::uint64_t token) const {
    if (!pending_ || pending_->token != token) {
        throw std::logic_error("Stale protocol callback token");
    }
}

void ProtocolViews::finish(std::uint64_t token, buffer const& bytes) {
    check_token(token);
    finish(token, ProtocolInput{pending_->sender, bytes, pending_->stream});
}

void ProtocolViews::finish(std::uint64_t token, ProtocolInput const& output) {
    finish_outputs(token, &output, 1);
}

void ProtocolViews::finish(std::uint64_t token, std::vector<ProtocolInput> const& outputs) {
    finish_outputs(token, outputs.data(), outputs.size());
}

void ProtocolViews::finish_outputs(std::uint64_t token, ProtocolInput const* outputs,
                                   std::size_t count) {
    check_token(token);
    const auto sender = pending_->sender;
    for (std::size_t index = 0; index < count; ++index) {
        auto const& output = outputs[index];
        if (output.sender != sender) {
            throw std::logic_error("Output sender changed within callback");
        }
    }

    if (mode_ == Mode::Observe) {
        if (pending_->original &&
            (count != 1 || outputs[0].bytes.string_view() != *pending_->original)) {
            untracked_rewrite_ = true;
            fork_error_ = "Protocol views unavailable: raw rewrite preceded session split";
        }
        pending_.reset();
        return;
    }

    // One callback may emit both request and QPACK-stream bytes. Observe the
    // exact ordered batch queued by the caller, without repeating inspectors.
    for (std::size_t index = 0; index < count; ++index) {
        auto const& output = outputs[index];
        observe(context(sender, Phase::Output), output, 0, true);
    }
    pending_.reset();
}

void ProtocolViews::abandon(std::uint64_t token) {
    check_token(token);
    // No output was delivered. Preserve that fact if the connection continues.
    buffer empty;
    finish(token, empty);
}

void ProtocolViews::inject(Endpoint recipient, buffer const& bytes) {
    inject(ProtocolInput{peer(recipient), bytes});
}

void ProtocolViews::inject(ProtocolInput const& output) {
    if (output.event == ProtocolEvent::Data && output.bytes.empty()) return;

    // A shared observation view cannot represent data seen by only one peer.
    // Never fork late from a state that already contains unmodified input.
    if (mode_ != Mode::Rewrite || !active()) {
        throw std::logic_error("Injection requires a prepared rewrite protocol view");
    }

    prepare_output();
    observe(context(output.sender, Phase::Output), output, 0, true);
}

void ProtocolViews::seed(Endpoint sender, buffer const& bytes, PayloadAnalysis* analysis) {
    if (sequence_ != 0 || split()) {
        throw std::logic_error("Cannot seed an active protocol conversation");
    }
    observe(shared_, sender, bytes, 0, true, analysis);
}

} // namespace sx::engine
