#ifndef FLOWCTX_HPP
#define FLOWCTX_HPP

#include <cstddef>
#include <cstdint>
#include <memory>

#include <apphostcx.hpp>
#include <inspect/protocol_views.hpp>

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

    Tx begin(Dir dir, buffer const& data, std::uint64_t read_bytes);
    void commit(Tx const& tx, buffer const& data);
    void discard(Tx const& tx);

    // Existing metadata consumers see the current INPUT endpoint. Output
    // observation never switches this selector or publishes another webhook.
    sx::engine::EngineCtx& engine() { return views_.context(active_endpoint_); }
    sx::engine::EngineCtx const& engine() const { return views_.context(active_endpoint_); }

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
    sx::engine::ProtocolViews views_;
    Endpoint active_endpoint_ = Endpoint::Client;
    Stats i2r_;
    Stats r2i_;
};

#endif
