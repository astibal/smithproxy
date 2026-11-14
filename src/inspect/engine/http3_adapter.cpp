#include <inspect/engine/http3_adapter.hpp>
#include <inspect/engine/http3.hpp>
#include <socle/common/base64.hpp>

namespace sx::engine::http::v3 {
namespace {

using E = ProtocolEndpoint;
using Event = ProtocolEvent;

char const* event_name(Event event) {
    switch (event) {
        case Event::Data: return "data";
        case Event::Fin: return "fin";
        case Event::Reset: return "reset";
        case Event::ConnectionClose: return "connection-close";
    }
    return "unknown";
}

socle::side_t side(E sender) {
    return sender == E::Client ? socle::side_t::LEFT : socle::side_t::RIGHT;
}

Http3Connection& connection(EngineCtx& ctx) {
    return std::any_cast<Http3Connection&>(ctx.state_data);
}

// QUIC variable-length integers are at most eight bytes. Retain only the
// incomplete frame prefix; DATA bodies are never buffered by this locator.
std::optional<std::pair<std::uint64_t, std::size_t>> varint(
    std::vector<unsigned char> const& bytes, std::size_t offset) {
    if (offset >= bytes.size()) return std::nullopt;
    const auto length = std::size_t{1} << (bytes[offset] >> 6U);
    if (bytes.size() - offset < length) return std::nullopt;

    std::uint64_t value = bytes[offset] & 0x3fU;
    for (std::size_t i = 1; i < length; ++i) value = (value << 8U) | bytes[offset + i];
    return std::pair{value, length};
}

struct FrameDescription {
    std::string_view name;
    std::string_view kind;
};

FrameDescription describe_frame(std::uint64_t type) {
    switch (type) {
        case 0: return {"DATA", "h3.data"};
        case 1: return {"HEADERS", "h3.headers"};
        case 3: return {"CANCEL_PUSH", "h3.cancel_push"};
        case 4: return {"SETTINGS", "h3.settings"};
        case 5: return {"PUSH_PROMISE", "h3.push_promise"};
        case 7: return {"GOAWAY", "h3.goaway"};
        case 13: return {"MAX_PUSH_ID", "h3.max_push_id"};
        default: return {"UNKNOWN", "h3.frame.payload"};
    }
}

L7PayloadHints observe_framing(Http3Stream::Direction& state,
                              ProtocolInput const& input,
                              PayloadAnnotations& annotations) {
    L7PayloadHints ranges;
    const auto& bytes = input.bytes;
    const auto* data = static_cast<unsigned char const*>(bytes.data());
    const auto stream_id = input.stream->id;
    const bool unidirectional = (stream_id & 2U) != 0;
    std::size_t cursor = 0;

    auto annotate = [&](std::size_t start, std::size_t end, std::string_view kind,
                        std::optional<std::uint64_t> frame = std::nullopt) {
        if (start == end) return;
        PayloadAnnotationAttributes attributes {
            {"stream_id", static_cast<std::int64_t>(stream_id)}
        };
        if (state.stream_type) {
            attributes["stream_type"] = static_cast<std::int64_t>(*state.stream_type);
        }
        if (frame) {
            attributes["frame_type"] = std::string(describe_frame(*frame).name);
            attributes["frame_type_id"] = static_cast<std::int64_t>(*frame);
        }
        if (!annotations.empty() && annotations.back().end == static_cast<std::int64_t>(start)
            && annotations.back().kind == kind && annotations.back().attributes == attributes) {
            annotations.back().end = static_cast<std::int64_t>(end);
        } else {
            annotations.push_back({static_cast<std::int64_t>(start),
                                   static_cast<std::int64_t>(end), std::string(kind),
                                   std::move(attributes)});
        }
    };

    // A unidirectional stream starts with its type, not an H3 frame header.
    // QPACK instructions and unknown stream types must never look like DATA.
    if (unidirectional && !state.stream_type) {
        const auto start = cursor;
        while (cursor < bytes.size() && !state.stream_type) {
            state.prefix.push_back(data[cursor++]);
            if (auto type = varint(state.prefix, 0)) {
                state.stream_type = type->first;
                state.prefix.clear();
            }
        }
        annotate(start, cursor, "h3.stream.type");
    }
    if (unidirectional && (!state.stream_type || *state.stream_type != 0)) {
        auto kind = state.stream_type == 2 ? "h3.qpack.encoder" :
                    state.stream_type == 3 ? "h3.qpack.decoder" : "h3.stream.payload";
        annotate(cursor, bytes.size(), kind);
        // Push streams and extension types remain opaque here. Their bytes
        // are not proven to contain no user content; report unknown ranges.
        const bool known_control = !state.stream_type || *state.stream_type == 2 ||
                                   *state.stream_type == 3;
        return known_control ? L7PayloadHints{{0, 0}} : L7PayloadHints{{-1, -1}};
    }

    while (cursor < bytes.size()) {
        if (!state.frame_type) {
            const auto start = cursor;
            while (cursor < bytes.size() && !state.frame_type) {
                state.prefix.push_back(data[cursor++]);
                const auto type = varint(state.prefix, 0);
                const auto length = type ? varint(state.prefix, type->second) : std::nullopt;
                if (!length) continue;

                state.frame_type = type->first;
                state.remaining = length->first;
                state.prefix.clear();
            }
            // Annotate only bytes in this callback. A partial header does not
            // claim a frame type until both varints have been read completely.
            annotate(start, cursor, "h3.frame.header", state.frame_type);
            if (!state.frame_type) break;
        }

        const auto count = std::min<std::uint64_t>(state.remaining, bytes.size() - cursor);
        annotate(cursor, cursor + count, describe_frame(*state.frame_type).kind,
                 state.frame_type);
        if (!unidirectional && *state.frame_type == 0 && count) {
            ranges.emplace_back(cursor, cursor + count);
        }
        cursor += count;
        state.remaining -= count;
        if (!state.remaining) state.frame_type.reset();
    }

    if (ranges.empty()) ranges.emplace_back(0, 0);
    return ranges;
}

void remember(Http3Connection& state, ProtocolInput const& input) {
    if (!state.replayable || !input.stream) return;
    if (input.bytes.size() > Http3Connection::maximum_history_bytes - state.history_bytes ||
        state.history.size() >= Http3Connection::maximum_history_events) {
        // Losing replay history does not disable live decoding. It only makes
        // a later exact fork unavailable, with a specific diagnostic to callers.
        state.replayable = false;
        state.history.clear();
        state.history_bytes = 0;
        return;
    }

    Http3Connection::SavedInput saved{input.sender, *input.stream, input.event,
                                    input.error_code, {}};
    if (!input.bytes.empty()) {
        const auto* data = static_cast<unsigned char const*>(input.bytes.data());
        saved.bytes.assign(data, data + input.bytes.size());
    }
    state.history_bytes += saved.bytes.size();
    state.history.push_back(std::move(saved));
}

void apply_headers(Http3Stream& stream, sx::quic::h3_headers_record const& record) {
    auto& direction = stream.directions[record.side == socle::side_t::LEFT ? 0 : 1];
    // Keep ordered fields and duplicates. Interim responses and trailers are
    // distinct sections; bound retained metadata independently of the decoder.
    if (direction.headers.size() < 16) direction.headers.push_back(record.fields);
    else direction.metadata_limit = "header-section-limit";

    auto status = std::find_if(record.fields.begin(), record.fields.end(), [](auto const& field) {
        return field.name == ":status";
    });
    const bool initial = record.side == socle::side_t::LEFT
        ? !direction.final_headers
        : status != record.fields.end() && !status->value.empty() && status->value.front() != '1';
    // Interim responses and trailers do not describe the final representation.
    // Reset on final headers even when content-encoding is absent.
    if (initial) {
        direction.encoding.clear();
        direction.final_headers = true;
    }

    auto& app = *stream.application;
    for (auto const& field : record.fields) {
        if (initial && field.name == "content-encoding") {
            if (!direction.encoding.empty()) direction.encoding += ", ";
            direction.encoding += field.value;
        }
        if (record.side != socle::side_t::LEFT) continue;

        if (field.name == ":method") app.http_data.method = field.value;
        else if (field.name == ":authority") app.http_data.host = field.value;
        else if (field.name == ":path") app.http_data.uri = field.value;
        else if (field.name == ":scheme") app.http_data.proto = field.value + "://";
        else if (field.name == "content-type") app.http_data.content_type = field.value;
        else if (field.name == "accept") app.http_data.accept = field.value;
        else if (field.name == "referer") app.http_data.referer = field.value;
    }
    if (!app.http_data.method.empty()) app.mark_populated();
}

std::unique_ptr<EngineCtx> fork_context(EngineCtx const& source) {
    auto const& log = log::http3;

    auto const& original = std::any_cast<Http3Connection const&>(source.state_data);
    _deb("ctx=%p fork replayable=%d history_events=%zu history_bytes=%zu",
         static_cast<void const*>(&source), original.replayable,
         original.history.size(), original.history_bytes);

    if (!original.replayable) {
        throw std::runtime_error("HTTP/3 fork unavailable: QPACK replay history limit exceeded");
    }

    // ls-qpack owns pointer-linked tables and blocked callbacks. Replaying the
    // bounded ordered journal builds independent allocations, including partial
    // instructions, without copying library internals or publishing observations.
    Http3Connection cloned;
    for (auto const& saved : original.history) {
        if (saved.event == Event::Data) {
            cloned.decoder->ingest(side(saved.sender), saved.stream.id,
                                   saved.bytes.data(), saved.bytes.size());
        } else {
            cloned.decoder->finish(side(saved.sender), saved.stream.id,
                                   saved.event == Event::Reset);
        }
    }

    cloned.streams = original.streams;
    for (auto& [key, stream] : cloned.streams) {
        stream.application = std::make_shared<app_HttpRequest>(*stream.application);
    }
    cloned.history = original.history;
    cloned.history_bytes = original.history_bytes;
    cloned.header_bytes = original.header_bytes;
    cloned.closed = original.closed;
    cloned.published_connection_status = original.published_connection_status;
    cloned.on_metadata = original.on_metadata;

    auto result = std::make_unique<EngineCtx>(source);
    result->payload_analysis = nullptr;
    result->application_data.reset();
    for (auto const& [key, stream] : original.streams) {
        if (stream.application == source.application_data) {
            result->application_data = cloned.streams.at(key).application;
            break;
        }
    }
    result->state_data = std::move(cloned);
    return result;
}

void publish(EngineCtx& ctx, ProtocolInput const& input, std::uint64_t id,
             socle::side_t field_side, std::string const& event,
             sx::quic::h3_headers_record const* record = nullptr) {
    auto& state = connection(ctx);
    if (ctx.protocol_only || !state.on_metadata) return;
    auto sender = field_side == socle::side_t::LEFT ? E::Client : E::Server;
    auto info = metadata(ctx, id, sender);
    info["side"] = field_side == socle::side_t::LEFT ? "L" : "R";
    info["protocol_event"] = event;
    info["protocol_endpoint"] = input.sender == E::Client ? "client" : "server";
    if (input.error_code) info["protocol_error"] = *input.error_code;
    if (record) {
        auto fields = nlohmann::json::array();
        std::string section = field_side == socle::side_t::LEFT ? "request" : "trailers";
        bool pseudo = false;
        for (auto const& field : record->fields) {
            fields.push_back({field.name, field.value});
            pseudo = pseudo || (!field.name.empty() && field.name.front() == ':');
            if (field.name == ":status") {
                info["flow.http3.status"] = field.value;
                section = !field.value.empty() && field.value.front() == '1' ? "interim" : "response";
            }
        }
        if (!pseudo) section = "trailers";
        info["flow.http3.header_section"] = section;
        info["flow.http3.headers"] = std::move(fields);
    }
    auto found = state.streams.lower_bound(ProtocolStream{id, 0});
    if (found != state.streams.end() && found->first.id == id) {
        found->second.directions[sender == E::Client ? 0 : 1].published_status =
            info["flow.http3.decode"].dump();
    }
    encode_metadata_bytes(info);
    state.on_metadata(id, std::move(info));
}

// A critical-stream failure changes every stream in this endpoint view.
// Scan only on a connection-state transition, not on every DATA fragment.
void publish_connection_status(EngineCtx& ctx, ProtocolInput const& input) {
    auto& state = connection(ctx);
    if (ctx.protocol_only || !state.on_metadata) return;
    auto status = state.decoder->connection_status();
    if (status == state.published_connection_status) return;
    state.published_connection_status = std::move(status);
    for (auto& [key, stream] : state.streams) {
        for (std::size_t index = 0; index < stream.directions.size(); ++index) {
            auto const& previous = stream.directions[index].published_status;
            if (previous.empty()) continue; // No observation published for this direction yet.
            auto sender = index == 0 ? E::Client : E::Server;
            if (metadata(ctx, key.id, sender)["flow.http3.decode"].dump() != previous) {
                publish(ctx, input, key.id, side(sender), "decode-status");
            }
        }
    }
}

class Http3Adapter final : public ProtocolAdapter {
public:
    bool owns_content_metadata() const override { return true; }

    bool owns(EngineCtx const& ctx) const override {
        return ctx.state_data.type() == typeid(Http3Connection);
    }

    Preparation prepare(EngineCtx& ctx, bool, buffer const&) const override {
        auto const& log = log::http3;

        // QUIC supplies the negotiated protocol before any stream input. Do
        // not sniff arbitrary TCP bytes for HTTP/3 or replay raw TCP history.
        if (owns(ctx)) return Preparation::Ready;
        if (ctx.negotiated_alpn != "h3") return Preparation::Unavailable;
        _deb("ctx=%p initialized from negotiated h3 ALPN", static_cast<void*>(&ctx));
        ctx.state_data = Http3Connection();
        ctx.status = EngineCtx::status_t::OK;
        return Preparation::Ready;
    }

    void select_stream(EngineCtx& ctx, ProtocolStream key) const override {
        auto& state = connection(ctx);
        auto found = state.streams.find(key);
        if (found == state.streams.end()) {
            if (state.streams.size() >= Http3Connection::maximum_streams) {
                ctx.application_data.reset();
                return;
            }
            found = state.streams.try_emplace(key).first;
            found->second.application->version = app_HttpRequest::HTTP_VER::HTTP3;
        }
        ctx.application_data = found->second.application;
    }

    void observe(EngineCtx&, bool, buffer const&, std::uint64_t) const override {
        throw std::logic_error("HTTP/3 input requires a transport stream identity");
    }

    void observe(EngineCtx& ctx, ProtocolInput const& input,
                 std::uint64_t read_bytes) const override {
        auto const& log = log::http3;

        auto& state = connection(ctx);
        // Correlate stream lifecycle without dumping payloads or header values.
        const auto endpoint = input.sender == E::Client ? "client" : "server";
        _deb("ctx=%p sender=%s event=%s stream=%s bytes=%zu error=%s",
             static_cast<void*>(&ctx), endpoint, event_name(input.event),
             input.stream ? std::to_string(input.stream->id).c_str() : "none",
             input.bytes.size(),
             input.error_code ? std::to_string(*input.error_code).c_str() : "none");

        if (input.event == Event::ConnectionClose) {
            state.closed = true;
            for (auto const& [key, stream] : state.streams)
                publish(ctx, input, key.id, side(input.sender), "connection-close");
            state.history.clear();
            state.replayable = false;
            return;
        }
        if (!input.stream || state.closed) return;

        select_stream(ctx, *input.stream);
        const auto current = state.streams.find(*input.stream);
        auto* direction = current == state.streams.end() ? nullptr
            : &current->second.directions[input.sender == E::Client ? 0 : 1];
        if (direction && direction->finished &&
            (input.event != Event::Reset || direction->reset_error)) return;
        remember(state, input);

        if (input.event != Event::Data) {
            if (direction) {
                direction->finished = true;
                if (input.event == Event::Reset) direction->reset_error = input.error_code.value_or(0);
            }
            state.decoder->finish(side(input.sender), input.stream->id,
                                  input.event == Event::Reset);
            publish_connection_status(ctx, input);
            publish(ctx, input, input.stream->id, side(input.sender),
                    input.event == Event::Reset ? "reset" : "fin");
            return;
        }

        const auto records = state.decoder->ingest(
            side(input.sender), input.stream->id,
            static_cast<unsigned char const*>(input.bytes.data()), input.bytes.size());
        for (auto const& record : records) {
            _deb("ctx=%p decoded headers stream=%llu side=%s fields=%zu",
                 static_cast<void*>(&ctx), static_cast<unsigned long long>(record.stream_id),
                 record.side == socle::side_t::LEFT ? "client" : "server", record.fields.size());

            // A QPACK encoder stream can release another stream's field section.
            // QUIC never reuses a wire ID within a connection.
            auto found = state.streams.lower_bound(ProtocolStream{record.stream_id, 0});
            if (found != state.streams.end() && found->first.id == record.stream_id) {
                std::size_t size = 0;
                for (auto const& field : record.fields) size += field.name.size() + field.value.size();
                if (size <= Http3Connection::maximum_header_bytes - state.header_bytes) {
                    state.header_bytes += size;
                    apply_headers(found->second, record);
                } else {
                    auto& target = found->second.directions[record.side == socle::side_t::LEFT ? 0 : 1];
                    target.metadata_limit = "header-bytes-limit";
                    target.encoding.clear();
                    target.final_headers = false;
                }
                // Includes records unblocked on another stream. Emit the actual
                // section even if the bounded retained history is exhausted.
                publish(ctx, input, record.stream_id, record.side, "headers", &record);
            }
        }

        publish_connection_status(ctx, input);
        if (!direction) {
            // Still feed the shared decoder above: a newly admitted critical
            // QPACK stream can unblock existing streams after our storage cap.
            publish(ctx, input, input.stream->id, side(input.sender), "decode-status");
            return;
        }
        auto& stream = current->second;
        const auto snapshot = metadata(ctx, input.stream->id, input.sender);
        auto current_status = snapshot["flow.http3.decode"].dump();
        if (current_status != direction->published_status) {
            _deb("ctx=%p sender=%s stream=%llu decode=%s",
                 static_cast<void*>(&ctx), endpoint,
                 static_cast<unsigned long long>(input.stream->id), current_status.c_str());
            publish(ctx, input, input.stream->id, side(input.sender), "decode-status");
        }

        PayloadAnnotations annotations;
        auto ranges = observe_framing(*direction, input, annotations);
        const auto encoding = snapshot["flow.http3.decode"].value("encoding_known", false)
            ? direction->encoding : std::string{};
        std::vector<std::string> encodings(ranges.size(), encoding);
        if (ranges == L7PayloadHints{{0, 0}}) encodings.assign(1, "");
        stream.application->observe_l7_payload(input.bytes.string_view(), read_bytes,
            std::move(ranges), std::move(encodings), std::move(annotations), ctx.payload_analysis);
    }

    std::unique_ptr<EngineCtx> fork(EngineCtx const& ctx) const override {
        return fork_context(ctx);
    }
};

} // namespace

void encode_metadata_bytes(nlohmann::json& value) {
    if (value.is_string()) {
        try {
            // Use the same UTF-8 validation as the webhook serializer.
            (void)value.dump();
        } catch (nlohmann::json::type_error const&) {
            auto const& bytes = value.get_ref<std::string const&>();
            auto encoded = libbase64::encode<std::string, char, unsigned char, true>(
                reinterpret_cast<unsigned char const*>(bytes.data()), bytes.size());
            value = {{"encoding", "base64"}, {"data", std::move(encoded)}};
        }
    } else if (value.is_structured()) {
        for (auto& item : value) encode_metadata_bytes(item);
    }
}

nlohmann::json diagnostics(ProtocolViews const& views, std::uint64_t stream_id) {
    if (!std::any_cast<Http3Connection>(&views.context(E::Client).state_data)) return {};
    nlohmann::json result = {{"split", views.split()}, {"stream_id", stream_id},
                             {"fork_error", views.fork_error()}};
    auto snapshot = [&](E endpoint) {
        auto const& ctx = views.context(endpoint);
        auto const& state = std::any_cast<Http3Connection const&>(ctx.state_data);
        return nlohmann::json {
            {"request", metadata(ctx, stream_id, E::Client)},
            {"response", metadata(ctx, stream_id, E::Server)},
            {"closed", state.closed}, {"replayable", state.replayable},
            {"history_bytes", state.history_bytes}, {"history_events", state.history.size()},
            {"header_bytes", state.header_bytes}, {"tracked_streams", state.streams.size()}
        };
    };
    result[views.split() ? "client" : "shared"] = snapshot(E::Client);
    if (views.split()) result["server"] = snapshot(E::Server);
    return result;
}

nlohmann::json metadata(EngineCtx const& ctx, std::uint64_t stream_id, ProtocolEndpoint sender) {
    auto const* state = std::any_cast<Http3Connection>(&ctx.state_data);
    if (!state) return {};
    auto found = state->streams.lower_bound(ProtocolStream{stream_id, 0});
    if (found != state->streams.end() && found->first.id != stream_id) found = state->streams.end();
    auto status = state->decoder->status(side(sender), stream_id);
    std::string reason;
    if (found == state->streams.end()) {
        status = "limited";
        reason = "stream-limit";
    } else {
        auto const& direction = found->second.directions[sender == E::Client ? 0 : 1];
        if (!direction.metadata_limit.empty()) {
            status = "limited";
            reason = direction.metadata_limit;
        }
        if (direction.reset_error) status = "reset";
    }
    if (reason.empty() && status == "invalid") reason = "protocol-error";
    if (reason.empty() && status == "limited") reason = "decoder-limit";
    nlohmann::json info = {{"protocol_metadata_version", 1},
        {"flow.http3.decode", {{"state", status}, {"reason", reason}, {"encoding_known", false}}}};
    if (found != state->streams.end()) {
        auto const& direction = found->second.directions[sender == E::Client ? 0 : 1];
        info["flow.http3.decode"]["encoding_known"] = direction.final_headers
            && status != "invalid" && status != "unavailable" && status != "limited" && status != "reset";
        auto const& http = found->second.application->http_data;
        auto put = [&](char const* key, std::string const& value) {
            if (!value.empty()) info[key] = value;
        };
        put("flow.http3.method", http.method);
        put("flow.http3.authority", http.host);
        put("flow.http3.path", http.uri);
        put("flow.http3.content_type", http.content_type);
        put("flow.http3.accept", http.accept);
        put("flow.http3.subprotocol", http.sub_proto);
        auto scheme = http.proto;
        if (scheme.size() >= 3 && scheme.substr(scheme.size() - 3) == "://") scheme.resize(scheme.size() - 3);
        put("flow.http3.scheme", scheme);
        if (!http.method.empty()) {
            info["flow.http3"] = true;
            put("flow.http3.url", found->second.application->request());
        }
    }
    encode_metadata_bytes(info);
    return info;
}

ProtocolAdapter const& protocol_adapter() {
    static const Http3Adapter adapter;
    return adapter;
}

} // namespace sx::engine::http::v3
