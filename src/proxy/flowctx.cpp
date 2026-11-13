#include <proxy/flowctx.hpp>

#include <proxy/mitmhost.hpp>
#include <inspect/engine/http3_adapter.hpp>
#include <inspect/http_diagnostics.hpp>

nlohmann::json FlowCtx::http_diagnostics() const {
    return sx::engine::http::diagnostics(protocol_views(), stream_);
}

nlohmann::json FlowCtx::protocol_diagnostics() const {
    if (!session_views_ || !stream_) return {};
    return sx::engine::http::v3::diagnostics(*session_views_, stream_->id);
}


void FlowCtx::attach(MitmHostCX& host, char leg) {
    const bool initiator = leg == 'L' || leg == 'l';

    if(initiator) {
        i_ = &host;
        app_ = host.app_context();
        engine().origin = i_;

        if(r_) r_->app_context(app_, true);
    } else {
        r_ = &host;
        if(not app_) app_ = host.app_context();
    }

    host.app_context(app_, true);
}

FlowCtx::Tx FlowCtx::begin(Dir dir, buffer const& data,
                           std::uint64_t read_bytes) {
    Tx tx {dir, data.size(), i_ != nullptr && not data.empty()};
    if(not tx.active) return tx;

    auto& count = stats(dir);
    count.raw_bytes += data.size();

    active_endpoint_ = dir == Dir::I2R ? Endpoint::Client : Endpoint::Server;
    const char side = dir == Dir::I2R ? 'r' : 'w';
    const bool ingested = i_->ingest(side, data);

    if (session_views_) {
        engine(); // Select this child's metadata before the synchronous pass.
        tx.protocol_token = session_views_->begin(
            sx::engine::ProtocolInput{active_endpoint_, data, stream_}, read_bytes);
        return tx;
    }

    if ((views_.active() || i_->opt_engines_enabled) &&
        views_.prepare(active_endpoint_, data, i_->flow(), ingested)) {
        tx.protocol_token = views_.begin(active_endpoint_, data, read_bytes);
        return tx;
    }

    // Other protocol engines retain their existing raw-flow path.
    i_->run_engine();

    // Framing works on the exact block delivered to content consumers.
    // The protocol engine above supplies connection state and classification.
    sx::engine::observe_unadapted_content(engine(), dir == Dir::I2R, data, read_bytes);

    return tx;
}

void FlowCtx::commit(Tx const& tx, buffer const& data) {
    if(not tx.active) return;

    auto& count = stats(tx.dir);
    count.out_bytes += data.size();
    if(data.size() != tx.raw_size) ++count.changed;

    // This is called after ALL modifiers and before queueing to the peer.
    // No ingest(), inspector, webhook or payload rewriting on this pass.
    if (tx.protocol_token) protocol_views().finish(tx.protocol_token, data);
}

void FlowCtx::discard(Tx const& tx) {
    if(not tx.active) return;
    ++stats(tx.dir).dropped;
    if (tx.protocol_token) protocol_views().abandon(tx.protocol_token);
}

void FlowCtx::inject(Dir dir, buffer const& data) {
    const auto recipient = dir == Dir::I2R ? Endpoint::Server : Endpoint::Client;
    if (session_views_) {
        const auto sender = dir == Dir::I2R ? Endpoint::Client : Endpoint::Server;
        session_views_->inject(sx::engine::ProtocolInput{sender, data, stream_});
    } else {
        views_.inject(recipient, data);
    }
    stats(dir).out_bytes += data.size();
}

void FlowCtx::transport_event(Dir dir, sx::engine::ProtocolEvent event,
                              std::optional<std::uint64_t> error) {
    if (!session_views_) return;
    buffer empty;
    active_endpoint_ = dir == Dir::I2R ? Endpoint::Client : Endpoint::Server;
    engine();
    const sx::engine::ProtocolInput input{active_endpoint_, empty, stream_, event, error};
    const auto token = session_views_->begin(input, 0);
    session_views_->finish(token, input);
}

FlowCtx::Stats& FlowCtx::stats(Dir dir) {
    return dir == Dir::I2R ? i2r_ : r2i_;
}
