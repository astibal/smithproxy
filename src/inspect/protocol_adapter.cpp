#include <inspect/protocol_adapter.hpp>
#include <inspect/engine/http.hpp>

namespace sx::engine::http::v2 {
void process_client_prefaced_bytes(EngineCtx&, buffer&);
void process_directional_bytes(EngineCtx&, socle::side_t, buffer&);
std::unique_ptr<EngineCtx> fork_context(EngineCtx const&);
}

namespace sx::engine {
namespace {

class Http2Adapter final : public ProtocolAdapter {
public:
    bool owns(EngineCtx const& ctx) const override {
        return ctx.state_data.type() == typeid(http::v2::Http2Connection);
    }

    Preparation prepare(EngineCtx& ctx, bool from_client,
                        buffer const& current) const override {
#ifndef USE_HTTP2
        return Preparation::Unavailable;
#else
        if (!ctx.negotiated_alpn.empty() && ctx.negotiated_alpn != "h2") {
            return Preparation::Unavailable;
        }

        if (owns(ctx)) return Preparation::Ready;

        const auto signature = std::dynamic_pointer_cast<MyDuplexFlowMatch>(ctx.signature);
        const bool preface = from_client &&
            http::v2::is_prior_knowledge_preface(current.string_view());
        const bool detected = ctx.negotiated_alpn == "h2" || preface ||
            (signature && signature->sig_engine == "http2");

        if (!detected) return Preparation::Unavailable;

        // A CONNECT/ALPN transition starts a new protocol: outer bytes are
        // not history of this parser. Otherwise retain a fragmented preface.
        const bool transition = ctx.state_data.has_value();
        ctx.state_data = http::v2::Http2Connection();
        ctx.state_info.reset();
        ctx.flow_seen.reset();
        ctx.status = EngineCtx::status_t::START;

        return transition || preface ? Preparation::Ready : Preparation::ReplayHistory;
#endif
    }

    void observe(EngineCtx& ctx, bool from_client, buffer const& bytes,
                 std::uint64_t read_bytes) const override {
        auto app = std::dynamic_pointer_cast<http::app_HttpRequest>(ctx.application_data);

        if (!ctx.application_data) {
            app = std::make_shared<http::app_HttpRequest>();
            ctx.application_data = app;
        }

        // An unrelated inspector owns its metadata; do not replace it.
        if (app) app->version = http::app_HttpRequest::HTTP_VER::HTTP2;

        auto input = bytes.view();

        if (from_client && ctx.status == EngineCtx::status_t::START) {
            http::v2::process_client_prefaced_bytes(ctx, input);
        } else {
            http::v2::process_directional_bytes(
                ctx, from_client ? socle::side_t::LEFT : socle::side_t::RIGHT, input);
        }

        // Each view owns its framing cursor, including incomplete frames.
        // The raw flow's offsets cannot describe modified output bytes.
        http::v2::observe_content(ctx, from_client ? 0U : 1U,
                                 bytes.string_view(), read_bytes, from_client);
    }

    std::unique_ptr<EngineCtx> fork(EngineCtx const& ctx) const override {
        return http::v2::fork_context(ctx);
    }
};

const Http2Adapter http2;
const ProtocolAdapter* const adapters[] = {&http2};

} // namespace

ProtocolAdapter const* protocol_adapter(EngineCtx const& ctx) {
    for (auto adapter : adapters) {
        if (adapter->owns(ctx)) return adapter;
    }

    return nullptr;
}

ProtocolAdapter const* prepare_protocol_adapter(
    EngineCtx& ctx, bool from_client, buffer const& current,
    ProtocolAdapter::Preparation& preparation) {
    for (auto adapter : adapters) {
        preparation = adapter->prepare(ctx, from_client, current);

        if (preparation != ProtocolAdapter::Preparation::Unavailable) return adapter;
    }

    preparation = ProtocolAdapter::Preparation::Unavailable;
    return nullptr;
}

void observe_unadapted_content(EngineCtx& ctx, bool from_client,
                               buffer const& bytes, std::uint64_t read_bytes) {
    http::observe_content(ctx, from_client ? 0U : 1U,
                          bytes.string_view(), read_bytes, from_client);
}

} // namespace sx::engine
