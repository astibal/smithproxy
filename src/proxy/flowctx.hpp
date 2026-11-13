#ifndef FLOWCTX_HPP
#define FLOWCTX_HPP

#include <cstddef>
#include <cstdint>
#include <memory>

#include <apphostcx.hpp>
#include <inspect/protocol_views.hpp>
#include <nlohmann/json.hpp>

class MitmHostCX;

class FlowCtx {
public:
    enum class Dir { I2R, R2I };

    struct Tx {
        Dir dir {Dir::I2R};
        std::size_t raw_size = 0;
        bool active = false;
        std::uint64_t protocol_token = 0;
    };

    void attach(MitmHostCX& host, char leg);

    void allow_rewrite(bool allowed) {
        using Mode = sx::engine::ProtocolViews::Mode;
        if (session_views_) {
            if (allowed) session_views_->enable_rewrite();
        } else {
            views_.set_mode(allowed ? Mode::Rewrite : Mode::Observe);
        }
    }

    // A multiplexed child borrows the parent session's protocol views. The
    // logical key is stable across the two transport legs and all callbacks.
    void bind_protocol(std::shared_ptr<sx::engine::ProtocolViews> views,
                       sx::engine::ProtocolStream stream) {
        session_views_ = std::move(views);
        stream_ = stream;
    }
    bool owns_content_metadata() const {
        return protocol_views().owns_content_metadata();
    }
    void transport_event(Dir dir, sx::engine::ProtocolEvent event,
                         std::optional<std::uint64_t> error = std::nullopt);

    Tx begin(Dir dir, buffer const& data, std::uint64_t read_bytes);
    void commit(Tx const& tx, buffer const& data);
    void discard(Tx const& tx);

    // Locally generated output: no raw-input ingest or input-byte accounting.
    void inject(Dir dir, buffer const& data);
    bool can_inject() const { return protocol_views().can_inject(); }

    // Existing metadata consumers see the current INPUT endpoint. Output
    // observation never switches this selector or publishes another webhook.
    sx::engine::EngineCtx& engine() {
        if (session_views_) return session_views_->stream_context(active_endpoint_, *stream_);
        return views_.context(active_endpoint_);
    }
    sx::engine::EngineCtx const& engine() const {
        if (session_views_) return session_views_->stream_context(active_endpoint_, *stream_);
        return views_.context(active_endpoint_);
    }
    nlohmann::json protocol_diagnostics() const;
    std::string const& protocol_fork_error() const { return protocol_views().fork_error(); }

private:
    struct Stats {
        std::uint64_t raw_bytes = 0;
        std::uint64_t out_bytes = 0;
        std::uint64_t changed = 0;
        std::uint64_t dropped = 0;
    };

    Stats& stats(Dir dir);

    std::shared_ptr<AppFlowCtx> app_;
    MitmHostCX* i_ = nullptr;
    MitmHostCX* r_ = nullptr;

    using Endpoint = sx::engine::ProtocolViews::Endpoint;
    sx::engine::ProtocolViews& protocol_views() {
        return session_views_ ? *session_views_ : views_;
    }
    sx::engine::ProtocolViews const& protocol_views() const {
        return session_views_ ? *session_views_ : views_;
    }

    sx::engine::ProtocolViews views_;
    std::shared_ptr<sx::engine::ProtocolViews> session_views_;
    std::optional<sx::engine::ProtocolStream> stream_;
    Endpoint active_endpoint_ = Endpoint::Client;
    Stats i2r_;
    Stats r2i_;
};

#endif
