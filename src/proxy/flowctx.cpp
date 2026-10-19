#include <proxy/flowctx.hpp>

#include <inspect/engine/http.hpp>
#include <proxy/mitmhost.hpp>

void FlowCtx::attach(MitmHostCX& host, char leg) {
    const bool initiator = leg == 'L' || leg == 'l';

    if(initiator) {
        i_ = &host;
        app_ = host.app_context();
        engine_.origin = i_;

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

    const char side = dir == Dir::I2R ? 'r' : 'w';
    i_->ingest(side, data);
    i_->run_engine();

    // Framing works on the exact block delivered to content consumers.
    // The protocol engine above supplies connection state and classification.
    sx::engine::http::observe_content(
        engine_, dir == Dir::I2R ? 0U : 1U,
        data.string_view(), read_bytes, dir == Dir::I2R);

    return tx;
}

void FlowCtx::commit(Tx const& tx, buffer const& data) {
    if(not tx.active) return;

    auto& count = stats(tx.dir);
    count.out_bytes += data.size();
    if(data.size() != tx.raw_size) ++count.changed;

    // This is the transaction boundary for future state rollback/replay.
    // Analysis deliberately precedes modifiers so webhooks see full metadata.
}

void FlowCtx::discard(Tx const& tx) {
    if(not tx.active) return;
    ++stats(tx.dir).dropped;
}

FlowCtx::Stats& FlowCtx::stats(Dir dir) {
    return dir == Dir::I2R ? i2r_ : r2i_;
}
