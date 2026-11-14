#include <proxy/quic/h3_replacement.hpp>
#include <inspect/engine/http3_response.hpp>
#include <inspect/engine/http3_constants.hpp>
#include <inspect/engine/http3_wire.hpp>
#include <array>
#include <algorithm>

namespace sx::quic {
using namespace multiflow;
namespace h3_error = sx::engine::http::v3::error_code;

namespace {

// QUIC stream ID bit 0 selects the initiator (0 = client); bit 1 selects
// directionality (0 = bidirectional). H3 requests use client bidirectional streams.
bool is_request_stream(std::uint64_t wire_id) {
    return (wire_id & 3U) == 0;
}

} // namespace

h3_replacement::h3_replacement(connection_ptr client, handler respond, proxy_limits limits)
    : client_(std::move(client)), respond_(std::move(respond)), limits_(limits) {
    control_ = client_->open_flow(direction::send_only);

    if (!client_->contains(control_)) {
        shutdown();
        return;
    }

    // Control stream with empty SETTINGS: no dynamic QPACK table, no blocked
    // streams. Client request field sections must therefore be self-contained.
    constexpr unsigned char settings[] {0, 4, 0};

    control_output_.append(settings, sizeof(settings));

    auto wire = client_->wire_flow_id(control_);

    if (wire) decoder_.ingest(socle::side_t::RIGHT, *wire, settings, sizeof(settings));
}

void h3_replacement::shutdown() {
    closing_ = true;
    client_->close(h3_error::no_error);
}

std::size_t h3_replacement::queued_bytes() const {
    std::size_t result = control_output_.size() - control_offset_;

    for (auto const& [id, value] : streams_) {
        result += value.output.size() - value.offset;
    }

    return result;
}

flow_summary h3_replacement::summary() const {
    flow_summary result;

    result.traffic_available = true;
    result.upload_bytes = received_;
    result.download_bytes = sent_;

    return result;
}

void h3_replacement::goaway(std::uint64_t next_id) {
    using sx::engine::http::v3::append_varint;
    using sx::engine::http::v3::varint_size;

    auto const payload_length = varint_size(next_id);

    if (payload_length == 0) {
        client_->close(h3_error::internal_error); // Cannot encode the GOAWAY boundary.
        return;
    }

    // GOAWAY = frame type, payload length, first rejected request stream ID.
    // Example: boundary 64 becomes 07 02 40 40 (a two-byte ID payload).
    append_varint(control_output_, 7);
    append_varint(control_output_, payload_length);
    append_varint(control_output_, next_id);

    closing_ = true; // Finish queued replies; never turn this connection into a bridge.
}

void h3_replacement::respond(h3_headers_record const& record) {
    if (!is_request_stream(record.stream_id) || record.side != socle::side_t::LEFT) return;

    auto found = std::find_if(streams_.begin(), streams_.end(), [&](auto const& entry) {
        return entry.second.wire_id == record.stream_id;
    });

    if (found == streams_.end() || found->second.responded) return;

    // The handler chooses the local page; this endpoint only frames and sends it.
    auto reply = respond_(record);

    if (reply.body.size() > 1024 * 1024 || queued_bytes() > 8 * 1024 * 1024) {
        client_->reset(found->second.handle, h3_error::excessive_load);
        found->second.finished = true;
        found->second.peer_finished = true;
        ++rejected_;
        return;
    }

    auto output = sx::engine::http::v3::make_response(reply.body, reply.status, reply.head_only);

    if (!output) {
        client_->reset(found->second.handle, h3_error::internal_error);
        found->second.finished = true;
        found->second.peer_finished = true;
        return;
    }

    found->second.output = std::move(*output);
    found->second.responded = true;

    if (reply.reconnect && !closing_) goaway(next_request_id_);
}

// Advance one queued output chunk and retain the offset on backpressure.
std::size_t h3_replacement::flush_output(flow_handle handle, buffer const& data,
                                       std::size_t& offset, std::size_t chunk_size) {
    if (offset == data.size()) return 0;

    auto result = client_->write(handle, data.data() + offset,
                                std::min(chunk_size, data.size() - offset));

    offset += result.size;
    sent_ += result.size;

    return result.size;
}

// Read and validate one stream, then advance its local response and FIN.
// False tells the connection pump to stop immediately after a critical close;
// progress includes bytes already consumed before that close.
bool h3_replacement::pump_stream_once(stream& value, std::size_t chunk_size,
                                     std::size_t& progress) {
    std::array<unsigned char, 16 * 1024> bytes {};

    if (!value.peer_finished) {
        auto input = client_->read(value.handle, bytes.data(), std::min(chunk_size, bytes.size()));

        received_ += input.size;
        progress += input.size;

        if (input.size) {
            for (auto& headers : decoder_.ingest(socle::side_t::LEFT, value.wire_id, bytes.data(), input.size)) {
                if (!value.request) value.request = std::move(headers);
            }
        }

        // EOF is the peer's FIN: no more bytes will arrive on this stream.
        // RESET aborts that stream instead. Neither closes the whole connection,
        // except when the peer closes an H3-critical control/QPACK stream.
        if (input.status == io_status::eof || input.status == io_status::reset) {
            value.peer_finished = true;

            if (decoder_.critical_stream(socle::side_t::LEFT, value.wire_id)) {
                client_->close(h3_error::closed_critical_stream);
                return false;
            }

            // Let the decoder distinguish a clean end from an aborted request.
            // An incomplete or reset request must never consume an override token.
            decoder_.finish(socle::side_t::LEFT, value.wire_id, input.status == io_status::reset);

            bool const request_stream = is_request_stream(value.wire_id);

            // Peer unidirectional streams have no response half to finish.
            if (!request_stream) value.finished = true;

            if (request_stream) {
                // A challenge changes authorization. Consume it only after
                // the entire request, including framing and length, is valid.
                if (input.status == io_status::eof && value.request &&
                    decoder_.complete_request(value.wire_id)) {
                    respond(*value.request);
                } else {
                    client_->reset(value.handle, h3_error::message_error);
                    value.finished = true;
                }
            }
        }
    }

    // Backpressure may require several passes; send FIN only after the body.
    if (value.responded && !value.finished) {
        progress += flush_output(value.handle, value.output, value.offset, chunk_size);

        if (value.offset == value.output.size()) value.finished = client_->finish(value.handle) == io_status::ok;
    }

    return true;
}

std::size_t h3_replacement::pump_once(std::size_t chunk_size) {
    if (!client_ || chunk_size == 0) return 0;

    // Apply transport lifecycle events before reading any stream data.
    for (auto const& event : client_->drain_events()) {
        if (event.type == event_type::connection_close) {
            streams_.clear();

            return 0;
        }

        if (!event.flow || *event.flow == control_) continue;

        if (event.type == event_type::flow_open) {
            auto wire = client_->wire_flow_id(*event.flow);

            bool const request_stream = wire && is_request_stream(*wire);
            bool const reject_after_goaway = closing_ && request_stream;
            bool const stream_limit_reached = streams_.size() >= limits_.max_flows;

            if (!wire || reject_after_goaway || stream_limit_reached) {
                client_->reset(*event.flow, h3_error::request_rejected);
                ++rejected_;
                continue;
            }

            // IDs of the same QUIC stream type advance by four. GOAWAY carries
            // the first request ID we will not accept, beyond all accepted IDs.
            if (request_stream) next_request_id_ = std::max(next_request_id_, *wire + 4);

            stream value;

            value.handle = *event.flow;
            value.wire_id = *wire;
            streams_.emplace(event.flow->id, std::move(value));
        } else if (event.type == event_type::reset) {
            auto found = streams_.find(event.flow->id);

            if (found != streams_.end()) {
                if (decoder_.critical_stream(socle::side_t::LEFT, found->second.wire_id)) {
                    client_->close(h3_error::closed_critical_stream);
                    return 0;
                }

                decoder_.finish(socle::side_t::LEFT, found->second.wire_id, true);
                streams_.erase(found);
            }
        }
    }

    // Send SETTINGS/GOAWAY on the connection control stream before responses.
    std::size_t progress = flush_output(control_, control_output_, control_offset_, chunk_size);

    for (auto& [id, value] : streams_) {
        if (!pump_stream_once(value, chunk_size, progress)) return progress;
    }

    if (decoder_.connection_status() == "invalid" || decoder_.connection_status() == "limited") {
        client_->close(h3_error::message_error);
    }

    // Keep a stream until both its request and response halves are finished.
    for (auto it = streams_.begin(); it != streams_.end();) {
        if (it->second.finished && it->second.peer_finished) it = streams_.erase(it);
        else ++it;
    }

    return progress;
}

} // namespace sx::quic
