#include "proxy/quic/spq1.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <stdexcept>

#include <traflog/pcaplog.hpp>

namespace sx::quic::spq1 {
namespace {

constexpr unsigned char version[] {'S', 'P', 'Q', '1'};
constexpr unsigned char header_end[] {'>', '>', '>'};

void append_u32(std::vector<unsigned char>& output, std::uint32_t value) {
    output.push_back(static_cast<unsigned char>(value >> 24));
    output.push_back(static_cast<unsigned char>(value >> 16));
    output.push_back(static_cast<unsigned char>(value >> 8));
    output.push_back(static_cast<unsigned char>(value));
}

void append_u64(std::vector<unsigned char>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<unsigned char>(value >> shift));
    }
}

void append_varint(std::vector<unsigned char>& output, std::uint64_t value) {
    if (value < (std::uint64_t{1} << 6)) {
        output.push_back(static_cast<unsigned char>(value));
    } else if (value < (std::uint64_t{1} << 14)) {
        auto const encoded = static_cast<std::uint16_t>(value | 0x4000U);
        output.push_back(static_cast<unsigned char>(encoded >> 8));
        output.push_back(static_cast<unsigned char>(encoded));
    } else if (value < (std::uint64_t{1} << 30)) {
        append_u32(output, static_cast<std::uint32_t>(value | 0x80000000ULL));
    } else if (value < (std::uint64_t{1} << 62)) {
        append_u64(output, value | 0xC000000000000000ULL);
    } else {
        throw std::out_of_range("SPQ1 QUIC variable integer exceeds 62 bits");
    }
}

std::vector<unsigned char> wrap_packet(
    connection_context& context, std::vector<unsigned char> const& frame) {
    auto const packet_number = context.next_packet_number.fetch_add(
        1, std::memory_order_relaxed);
    auto const payload_length = 4 + 1 + context.alpn.size() + frame.size();

    std::vector<unsigned char> output;
    output.reserve(payload_length + 24);
    output.push_back(0xD3); // Long header, fixed bit, private data type, 4-byte PN.
    output.insert(output.end(), std::begin(version), std::end(version));
    output.push_back(8); // The destination ID is the full listener session ID.
    append_u64(output, context.session_id);
    output.push_back(0); // Synthetic packets do not need a source connection ID.
    append_varint(output, payload_length);
    append_u32(output, packet_number);
    output.push_back(static_cast<unsigned char>(context.alpn.size()));
    output.insert(output.end(), context.alpn.begin(), context.alpn.end());
    output.insert(output.end(), frame.begin(), frame.end());
    return output;
}

} // namespace

std::vector<unsigned char> encode_stream_packet(
    stream_context const& context, std::uint64_t offset,
    unsigned char const* data, std::size_t size, bool fin) {
    if (!context.connection) throw std::invalid_argument("SPQ1 connection context is missing");
    if (size != 0 && !data) throw std::invalid_argument("SPQ1 plaintext pointer is missing");
    if (context.connection->alpn.size() > std::numeric_limits<unsigned char>::max()) {
        throw std::length_error("SPQ1 ALPN identifier exceeds 255 bytes");
    }

    // Build the STREAM frame separately because the QUIC-shaped long header
    // carries its complete encoded length before the packet number.
    std::vector<unsigned char> frame;
    frame.reserve(size + 32);
    frame.push_back(static_cast<unsigned char>(0x0E | (fin ? 0x01 : 0x00)));
    append_varint(frame, context.stream_id);
    append_varint(frame, offset);
    append_varint(frame, size);
    frame.insert(frame.end(), std::begin(header_end), std::end(header_end));
    if (size != 0) frame.insert(frame.end(), data, data + size);

    return wrap_packet(*context.connection, frame);
}

std::vector<unsigned char> encode_h3_headers_packet(
    connection_context& context, h3_headers_record const& record) {
    if (context.alpn.size() > std::numeric_limits<unsigned char>::max()) {
        throw std::length_error("SPQ1 ALPN identifier exceeds 255 bytes");
    }

    // Private extension 0xFACE carries the QPACK result. Keeping this separate
    // from the raw STREAM frame preserves byte-exact capture and lets older
    // dissectors safely ignore semantic records they do not understand.
    std::vector<unsigned char> payload;
    payload.push_back(1); // Semantic record type: decoded H3 HEADERS.
    append_varint(payload, record.stream_id);
    append_varint(payload, record.fields.size());
    for (auto const& field : record.fields) {
        append_varint(payload, field.name.size());
        payload.insert(payload.end(), field.name.begin(), field.name.end());
        append_varint(payload, field.value.size());
        payload.insert(payload.end(), field.value.begin(), field.value.end());
    }
    payload.insert(payload.end(), std::begin(header_end), std::end(header_end));

    std::vector<unsigned char> frame;
    append_varint(frame, 0xFACE);
    append_varint(frame, payload.size());
    frame.insert(frame.end(), payload.begin(), payload.end());
    return wrap_packet(context, frame);
}

stream_log::stream_log(std::unique_ptr<socle::baseTrafficLogger> output,
                       stream_context context)
    : output_(std::move(output)), context_(std::move(context)) {}

stream_log::~stream_log() {
    // A MitmProxy is destroyed only after its buffered stream data has been
    // handled. Emit synthetic FIN records last so Wireshark can close streams.
    for (auto side : {socle::side_t::LEFT, socle::side_t::RIGHT}) {
        auto const index = side_index(side);
        if (observed_[index] && !finished_[index]) finish(side);
    }
}

void stream_log::write(socle::side_t side, buffer const& data) {
    auto const* cursor = static_cast<unsigned char const*>(data.data());
    std::size_t remaining = data.size();
    while (remaining != 0) {
        auto const chunk = std::min(remaining, max_plaintext_per_packet);
        emit(side, cursor, chunk, false);
        cursor += chunk;
        remaining -= chunk;
    }

    // Semantic decoding is observational. Malformed H3/QPACK must never alter
    // forwarding or suppress the byte-exact SPQ1 STREAM record above.
    try {
        if (context_.connection && context_.connection->h3_decoder) {
            auto records = context_.connection->h3_decoder->ingest(
                side, context_.stream_id,
                static_cast<unsigned char const*>(data.data()), data.size());
            for (auto const& record : records) emit(record);
        }
    } catch (std::exception const&) {
        // Drop semantic enrichment only; raw stream capture is already stored.
    }
}

void stream_log::write(socle::side_t side, std::string const& comment) {
    if (output_) output_->write(side, comment);
}

void stream_log::finish(socle::side_t side) {
    auto const index = side_index(side);
    if (finished_[index]) return;
    finished_[index] = true;
    emit(side, nullptr, 0, true);
}

void stream_log::emit(socle::side_t side, unsigned char const* data,
                      std::size_t size, bool fin) {
    // Honour the regular capture kill switch even for FIN records emitted by
    // our destructor, which bypass baseTrafficLogger::write_left/write_right.
    if (!status() || !output_ || !context_.connection) return;
    auto const index = side_index(side);
    try {
        auto encoded = encode_stream_packet(context_, offsets_[index], data, size, fin);
        buffer packet(encoded.data(), encoded.size());
        output_->write(side, packet);
        offsets_[index] += size;
        observed_[index] = observed_[index] || size != 0;
    } catch (std::exception const&) {
        // Capture must never break the proxied data path. Invalid metadata or
        // allocation failure drops only this synthetic export record.
    }
}

void stream_log::emit(h3_headers_record const& record) {
    if (!status() || !output_ || !context_.connection) return;
    try {
        auto encoded = encode_h3_headers_packet(*context_.connection, record);
        buffer packet(encoded.data(), encoded.size());
        output_->write(record.side, packet);
    } catch (std::exception const&) {
        // As above, semantic capture is never allowed to affect proxy traffic.
    }
}

std::size_t stream_log::side_index(socle::side_t side) {
    return side == socle::side_t::RIGHT ? 1U : 0U;
}

std::unique_ptr<socle::baseTrafficLogger> stream_log_adapter::wrap(
    std::unique_ptr<socle::baseTrafficLogger> output) {
    // SPQ1 is a packet-capture representation. Stream-oriented sinks retain
    // their normal payload format and pass through unchanged.
    auto* pcap = dynamic_cast<socle::traflog::PcapLog*>(output.get());
    if (!pcap || !context_.connection) return output;

    pcap->details.next_proto = socle::pcap::connection_details::UDP;
    pcap->details.gre_key = static_cast<std::uint32_t>(
        context_.connection->session_id & 0xFFFFFFFFULL);
    return std::make_unique<stream_log>(std::move(output), context_);
}

} // namespace sx::quic::spq1
