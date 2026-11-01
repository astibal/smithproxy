#include <inspect/engine/http1_adapter.hpp>
#include <inspect/engine/http.hpp>
#include <inspect/protocol_adapter.hpp>

namespace sx::engine::http::v1 {
namespace {

class Http1Adapter final : public ProtocolAdapter {
public:
    bool owns(EngineCtx const& ctx) const override {
        const bool h1_alpn = ctx.negotiated_alpn.empty() ||
            ctx.negotiated_alpn == "http/1.1" || ctx.negotiated_alpn == "http/1.0";
        return h1_alpn && ctx.state_data.type() == typeid(Http1Connection);
    }

    Preparation prepare(EngineCtx& ctx, bool,
                        buffer const&) const override {
        if (!ctx.negotiated_alpn.empty() && ctx.negotiated_alpn != "http/1.1" &&
                ctx.negotiated_alpn != "http/1.0") {
            return Preparation::Unavailable;
        }
        if (owns(ctx)) {
            return Preparation::Ready;
        }

        const auto signature = std::dynamic_pointer_cast<MyDuplexFlowMatch>(ctx.signature);
        const bool detected = ctx.negotiated_alpn == "http/1.1" ||
            ctx.negotiated_alpn == "http/1.0" ||
            (signature && signature->sig_engine == "http1");
        if (!detected || ctx.state_data.has_value()) {
            return Preparation::Unavailable;
        }

        // Detection may finish after earlier reads. Seed only the preceding
        // history; ProtocolViews observes the current callback exactly once.
        ctx.state_data = Http1Connection();
        return Preparation::ReplayHistory;
    }

    void observe(EngineCtx& ctx, bool from_client, buffer const& bytes,
                 std::uint64_t read_bytes) const override {
        // Keep request identity and inspector effects on the original input
        // path. Output advances framing only and never rescans raw history.
        if (!ctx.protocol_only && ctx.origin && from_client) {
            start(ctx);
        }

        if (!ctx.application_data) {
            auto app = std::make_shared<app_HttpRequest>();
            app->version = app_HttpRequest::HTTP_VER::HTTP_1;
            ctx.application_data = app;
        }

        const auto direction = from_client ? 0U : 1U;
        const auto app = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
        if (app && app->version == app_HttpRequest::HTTP_VER::HTTP_1) {
            observe_content(ctx, direction, bytes.string_view(), read_bytes, !from_client);
        } else {
            // An unrelated inspector owns its metadata. Still advance native
            // framing so reverse output cannot use a stale method queue.
            auto& connection = std::any_cast<Http1Connection&>(ctx.state_data);
            connection.observe(direction, bytes.string_view(), !from_client);
        }
    }

    std::unique_ptr<EngineCtx> fork(EngineCtx const& ctx) const override {
        const auto* connection = std::any_cast<Http1Connection>(&ctx.state_data);
        if (!connection) {
            throw std::logic_error("Protocol fork requires initialized HTTP/1 state");
        }

        // H1 framing buffers and the request-method FIFO have value semantics.
        // Each endpoint must retain only the requests it has actually seen.
        auto copy = std::make_unique<EngineCtx>(ctx);
        copy->state_data = *connection;
        copy->payload_analysis = nullptr;

        if (auto app = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data)) {
            copy->application_data = std::make_shared<app_HttpRequest>(*app);
        } else {
            copy->application_data.reset();
        }

        return copy;
    }
};

} // namespace

ProtocolAdapter const& protocol_adapter() {
    static const Http1Adapter adapter;
    return adapter;
}

} // namespace sx::engine::http::v1
