#include <inspect/engine/http.hpp>
#include <inspect/protocol_adapter.hpp>

namespace sx::engine {
namespace {

using http::v2::Http2Connection;

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

} // namespace

std::unique_ptr<EngineCtx> EngineCtx::protocol_fork() const {
    auto adapter = protocol_adapter(*this);

    if (!adapter) {
        throw std::logic_error("Protocol fork requires an initialized protocol adapter");
    }

    return adapter->fork(*this);
}

namespace http::v2 {

std::unique_ptr<EngineCtx> fork_context(EngineCtx const& source) {
    const auto* connection = std::any_cast<Http2Connection>(&source.state_data);

    if (!connection) {
        throw std::logic_error("Protocol fork requires initialized HTTP/2 state");
    }

    auto copy = std::make_unique<EngineCtx>(source);
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

} // namespace http::v2

ProtocolCheckpoint EngineCtx::protocol_snapshot() const {
    const auto* connection = std::any_cast<Http2Connection>(&state_data);

    if (!connection) {
        throw std::logic_error("Protocol snapshot requires initialized HTTP/2 state");
    }

    // Do not accidentally snapshot an unrelated engine's positional payload.
    if (state_info.has_value() &&
        state_info.type() != typeid(http::v2::state_data_t)) {
        throw std::logic_error("Unsupported protocol position in HTTP/2 engine");
    }

    auto saved = clone_protocol(*connection);
    auto saved_position = state_info;
    auto saved_seen = flow_seen;
    auto saved_status = status;

    return ProtocolCheckpoint(this,
        [saved = std::move(saved), saved_position = std::move(saved_position),
         saved_seen, saved_status](EngineCtx& target,
                                  std::function<void()> const& rewind_flow) {
            if (target.state_data.type() != typeid(Http2Connection)) {
                throw std::logic_error("Protocol changed since checkpoint creation");
            }

            // Construct everything which can allocate before changing target.
            // Clone on EVERY restore so repeated restores cannot mutate the
            // checkpoint through shared HPACK decoder pointers.
            std::any restored = clone_protocol(saved);
            std::any position = saved_position;

            // Flow restoration allocates its deque before moving any blocks.
            // If preparation fails, both the live flow and engine stay intact.
            if (rewind_flow) rewind_flow();

            target.state_data.swap(restored);
            target.state_info.swap(position);
            target.flow_seen = saved_seen;
            target.status = saved_status;
        });
}

ProtocolCheckpoint EngineCtx::protocol_snapshot(duplexFlow& flow) const {
    auto checkpoint = protocol_snapshot();
    checkpoint.rewind_flow_ = [journal = flow.snapshot()] {
        journal.restore();
    };
    return checkpoint;
}

} // namespace sx::engine
