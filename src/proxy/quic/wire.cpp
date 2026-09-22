#include "proxy/quic/wire.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace sx::quic {
namespace {

constexpr std::size_t maximum_connection_id_size = 20;

std::uint32_t read_u32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24U)
        | (static_cast<std::uint32_t>(data[1]) << 16U)
        | (static_cast<std::uint32_t>(data[2]) << 8U)
        | static_cast<std::uint32_t>(data[3]);
}

packet_type decode_long_type(std::uint32_t version, std::uint8_t first_byte) {
    auto const type_bits = static_cast<std::uint8_t>((first_byte >> 4U) & 0x03U);
    if (version == version_1) {
        constexpr packet_type types[] = {
            packet_type::initial,
            packet_type::zero_rtt,
            packet_type::handshake,
            packet_type::retry,
        };
        return types[type_bits];
    }
    if (version == version_2) {
        constexpr packet_type types[] = {
            packet_type::retry,
            packet_type::initial,
            packet_type::zero_rtt,
            packet_type::handshake,
        };
        return types[type_bits];
    }
    return packet_type::unknown;
}

parse_result failure(header parsed, parse_error error, std::size_t offset) {
    return { std::move(parsed), error, offset };
}

} // namespace

varint_result parse_varint(const std::uint8_t* data, std::size_t size) {
    if (!data || size == 0) return { 0, 0, parse_error::truncated };

    auto const encoded_size = std::size_t { 1 } << (data[0] >> 6U);
    if (encoded_size > size) return { 0, encoded_size, parse_error::truncated };

    std::uint64_t value = data[0] & 0x3fU;
    for (std::size_t i = 1; i < encoded_size; ++i) {
        value = (value << 8U) | data[i];
    }
    return { value, encoded_size, parse_error::none };
}

parse_result parse_header(const std::uint8_t* data, std::size_t size) {
    header parsed;
    if (!data || size == 0) return failure(std::move(parsed), parse_error::empty, 0);

    parsed.first_byte = data[0];
    bool const long_header = (data[0] & 0x80U) != 0;
    bool const fixed_bit = (data[0] & 0x40U) != 0;

    if (!long_header) {
        if (!fixed_bit) return failure(std::move(parsed), parse_error::not_quic, 0);
        parsed.form = packet_form::short_header;
        parsed.packet_number_offset = 1;
        parsed.packet_end = size;
        return { std::move(parsed), parse_error::none, 0 };
    }

    parsed.form = packet_form::long_header;
    if (size < 6) return failure(std::move(parsed), parse_error::truncated, size);
    parsed.version = read_u32(data + 1);

    // Version Negotiation deliberately has no fixed-bit requirement.
    if (parsed.version != 0 && !fixed_bit) {
        return failure(std::move(parsed), parse_error::not_quic, 0);
    }

    std::size_t offset = 5;
    auto const destination_size = data[offset++];
    if (destination_size > maximum_connection_id_size) {
        return failure(std::move(parsed), parse_error::invalid_connection_id, offset - 1);
    }
    if (destination_size > size - offset) {
        return failure(std::move(parsed), parse_error::truncated, offset);
    }
    parsed.destination_connection_id.assign(data + offset, data + offset + destination_size);
    offset += destination_size;

    if (offset == size) return failure(std::move(parsed), parse_error::truncated, offset);
    auto const source_size = data[offset++];
    if (source_size > maximum_connection_id_size) {
        return failure(std::move(parsed), parse_error::invalid_connection_id, offset - 1);
    }
    if (source_size > size - offset) {
        return failure(std::move(parsed), parse_error::truncated, offset);
    }
    parsed.source_connection_id.assign(data + offset, data + offset + source_size);
    offset += source_size;

    if (parsed.version == 0) {
        parsed.type = packet_type::version_negotiation;
        parsed.packet_number_offset = offset;
        parsed.packet_end = size;
        return { std::move(parsed), parse_error::none, 0 };
    }

    parsed.type = decode_long_type(parsed.version, parsed.first_byte);
    if (parsed.type == packet_type::retry || parsed.type == packet_type::unknown) {
        parsed.packet_number_offset = offset;
        parsed.packet_end = size;
        return { std::move(parsed), parse_error::none, 0 };
    }

    if (parsed.type == packet_type::initial) {
        auto const token_size = parse_varint(data + offset, size - offset);
        if (!token_size) return failure(std::move(parsed), token_size.error, offset);
        offset += token_size.encoded_size;
        if (token_size.value > size - offset) {
            return failure(std::move(parsed), parse_error::truncated, offset);
        }
        offset += static_cast<std::size_t>(token_size.value);
    }

    auto const payload_size = parse_varint(data + offset, size - offset);
    if (!payload_size) return failure(std::move(parsed), payload_size.error, offset);
    offset += payload_size.encoded_size;
    parsed.packet_number_offset = offset;
    parsed.protected_payload_length = payload_size.value;

    if (payload_size.value > std::numeric_limits<std::size_t>::max() - offset) {
        return failure(std::move(parsed), parse_error::invalid_length, offset);
    }
    parsed.packet_end = offset + static_cast<std::size_t>(payload_size.value);
    if (parsed.packet_end > size) {
        return failure(std::move(parsed), parse_error::truncated, offset);
    }
    return { std::move(parsed), parse_error::none, 0 };
}

std::string to_string(packet_type value) {
    switch (value) {
        case packet_type::unknown: return "unknown";
        case packet_type::version_negotiation: return "version-negotiation";
        case packet_type::initial: return "initial";
        case packet_type::zero_rtt: return "0-rtt";
        case packet_type::handshake: return "handshake";
        case packet_type::retry: return "retry";
    }
    return "unknown";
}

std::string to_string(parse_error value) {
    switch (value) {
        case parse_error::none: return "none";
        case parse_error::empty: return "empty";
        case parse_error::not_quic: return "not-quic";
        case parse_error::truncated: return "truncated";
        case parse_error::invalid_connection_id: return "invalid-connection-id";
        case parse_error::invalid_varint: return "invalid-varint";
        case parse_error::invalid_length: return "invalid-length";
    }
    return "unknown";
}

} // namespace sx::quic
