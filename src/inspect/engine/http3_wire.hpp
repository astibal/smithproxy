#ifndef SX_HTTP3_WIRE_HPP
#define SX_HTTP3_WIRE_HPP

#include <buffer.hpp>
#include <array>
#include <cstddef>
#include <cstdint>

namespace sx::engine::http::v3 {

// HTTP/3 frame types, lengths and stream IDs use QUIC variable-length integers.
// Two high bits encode the width, leaving 6, 14, 30 or 62 bits for the value.
// Zero means the value cannot be represented by a QUIC varint.
constexpr std::size_t varint_size(std::uint64_t value) {
    if (value < (std::uint64_t{1} << 6)) return 1;
    if (value < (std::uint64_t{1} << 14)) return 2;
    if (value < (std::uint64_t{1} << 30)) return 4;
    if (value < (std::uint64_t{1} << 62)) return 8;

    return 0;
}

// Append the shortest encoding in network byte order. For example, 63 is 3f,
// while 64 needs two bytes: 40 40. Invalid values leave the output unchanged.
inline bool append_varint(buffer& output, std::uint64_t value) {
    auto const length = varint_size(value);

    if (length == 0) return false;

    std::array<unsigned char, 8> bytes {};

    for (std::size_t i = 0; i < length; ++i) {
        bytes[length - i - 1] = static_cast<unsigned char>(value >> (8 * i));
    }

    // Width tags 00, 01, 10, 11 select 1, 2, 4, 8 bytes respectively.
    // The value fits below these two bits because varint_size checked its range.
    auto const width_tag = length == 1 ? 0x00 : length == 2 ? 0x40 : length == 4 ? 0x80 : 0xc0;

    bytes[0] |= static_cast<unsigned char>(width_tag);
    output.append(bytes.data(), length);

    return true;
}

} // namespace sx::engine::http::v3
#endif
