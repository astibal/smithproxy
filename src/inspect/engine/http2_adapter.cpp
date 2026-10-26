#include <inspect/engine/http2_adapter.hpp>
#include <inspect/engine/http.hpp>
#include <inspect/protocol_adapter.hpp>

namespace sx::engine::http::v2 {

// Internal parser entry points shared with the raw-flow HTTP engine.
void process_client_prefaced_bytes(EngineCtx&, buffer&);
void process_directional_bytes(EngineCtx&, socle::side_t, buffer&);

namespace {

Http2Connection clone_protocol(Http2Connection const& source) {
    // Maps, pending vectors and boundary trackers have value semantics.
    // buffer can also be a non-owning view: detach stream buffers explicitly.
    auto copy = source;

    for (auto const& [id, stream] : source.streams) {
        auto& cloned = copy.streams.at(id);
        buffer body;
        body.assign(stream.doh_response_body_.data(), stream.doh_response_body_.size());
        cloned.doh_response_body_ = std::move(body);

        if (stream.gzip) {
            buffer compressed;
            compressed.assign(stream.gzip->in.data(), stream.gzip->in.size());
            cloned.gzip->in = std::move(compressed);
        }
    }

#ifdef USE_HPACK
    if (source.request_decoder) {
        copy.request_decoder =
            std::make_shared<HPACK::decoder_t>(*source.request_decoder);
    }

    if (source.response_decoder) {
        copy.response_decoder =
            std::make_shared<HPACK::decoder_t>(*source.response_decoder);
    }
#endif

    return copy;
}

std::unique_ptr<EngineCtx> fork_context(EngineCtx const& source) {
    const auto* connection = std::any_cast<Http2Connection>(&source.state_data);

    if (!connection) {
        throw std::logic_error("Protocol fork requires initialized HTTP/2 state");
    }

    auto copy = std::make_unique<EngineCtx>(source);
    // Callback-local scratch space belongs to the observation scope, never
    // to a newly independent context.
    copy->payload_analysis = nullptr;
    copy->state_data = clone_protocol(*connection);

    // Endpoint observations must not overwrite each other's webhook metadata.
    // Non-HTTP inspector data belongs to the original input context only.
    if (auto app = std::dynamic_pointer_cast<http::app_HttpRequest>(source.application_data)) {
        copy->application_data = std::make_shared<http::app_HttpRequest>(*app);
    } else {
        copy->application_data.reset();
    }

    return copy;
}


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

} // namespace

ProtocolAdapter const& protocol_adapter() {
    static const Http2Adapter adapter;
    return adapter;
}

} // namespace sx::engine::http::v2
