#ifndef SMITHPROXY_QUIC_WIRE_HPP
#define SMITHPROXY_QUIC_WIRE_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sx::quic {

constexpr std::uint32_t version_1 = 0x00000001U;
constexpr std::uint32_t version_2 = 0x6b3343cfU;

/** QUIC's invariant distinction between short and long packet headers. */
enum class packet_form {
    short_header,
    long_header,
};

/** Packet types identifiable before removing header protection. */
enum class packet_type {
    unknown,
    version_negotiation,
    initial,
    zero_rtt,
    handshake,
    retry,
};

/** Precise reason why invariant-header parsing stopped. */
enum class parse_error {
    none,
    empty,
    not_quic,
    truncated,
    invalid_connection_id,
    invalid_varint,
    invalid_length,
};

/**
 * Parsed invariant and long-header fields used for routing/diagnostics.
 * packet_number_offset marks the protected boundary; this parser intentionally
 * does not implement keys, header protection, frame parsing, or payload crypto.
 */
struct header {
    packet_form form = packet_form::short_header;
    packet_type type = packet_type::unknown;
    std::uint8_t first_byte = 0;
    std::uint32_t version = 0;
    std::vector<std::uint8_t> destination_connection_id;
    std::vector<std::uint8_t> source_connection_id;
    std::size_t packet_number_offset = 0;
    std::optional<std::uint64_t> protected_payload_length;
    std::size_t packet_end = 0;
};

/** Header parse result with the byte offset nearest to a malformed field. */
struct parse_result {
    header value;
    parse_error error = parse_error::none;
    std::size_t error_offset = 0;

    explicit operator bool() const { return error == parse_error::none; }
};

/** QUIC variable-length integer result, including consumed wire bytes. */
struct varint_result {
    std::uint64_t value = 0;
    std::size_t encoded_size = 0;
    parse_error error = parse_error::none;

    explicit operator bool() const { return error == parse_error::none; }
};

/** Parse one QUIC varint without reading beyond size. */
varint_result parse_varint(const std::uint8_t* data, std::size_t size);
/** Parse the unprotected portion of one QUIC packet. */
parse_result parse_header(const std::uint8_t* data, std::size_t size);

inline parse_result parse_header(std::vector<std::uint8_t> const& packet) {
    return parse_header(packet.data(), packet.size());
}

std::string to_string(packet_type value);
std::string to_string(parse_error value);

} // namespace sx::quic

#endif // SMITHPROXY_QUIC_WIRE_HPP
