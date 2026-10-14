#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace sx::comm::wire {

inline constexpr std::array<std::byte, 3> magic{
    std::byte{0}, std::byte{'S'}, std::byte{'C'}};
inline constexpr std::uint8_t version = 1;
inline constexpr std::size_t header_size = 13;
inline constexpr std::size_t max_payload = 64U * 1024U;

struct Header {
    std::uint8_t opcode = 0;
    int status = 0;
    std::uint32_t payload_size = 0;
};

inline void put_u32(std::byte* destination, std::uint32_t value) {
    destination[0] = std::byte{static_cast<std::uint8_t>(value >> 24U)};
    destination[1] = std::byte{static_cast<std::uint8_t>(value >> 16U)};
    destination[2] = std::byte{static_cast<std::uint8_t>(value >> 8U)};
    destination[3] = std::byte{static_cast<std::uint8_t>(value)};
}

inline std::uint32_t get_u32(const std::byte* source) {
    return (std::to_integer<std::uint32_t>(source[0]) << 24U)
        | (std::to_integer<std::uint32_t>(source[1]) << 16U)
        | (std::to_integer<std::uint32_t>(source[2]) << 8U)
        | std::to_integer<std::uint32_t>(source[3]);
}

inline bool decode_header(const std::byte* data, std::size_t size, Header& result) {
    if(!data || size < header_size || data[0] != magic[0] || data[1] != magic[1]
       || data[2] != magic[2] || data[3] != std::byte{version}) return false;
    result.opcode = std::to_integer<std::uint8_t>(data[4]);
    result.status = static_cast<int>(get_u32(data + 5));
    result.payload_size = get_u32(data + 9);
    return result.payload_size <= max_payload;
}

inline std::vector<std::byte> encode(std::uint8_t opcode, int status,
                                     const std::string& payload) {
    std::vector<std::byte> result(header_size + payload.size());
    result[0] = magic[0]; result[1] = magic[1]; result[2] = magic[2];
    result[3] = std::byte{version}; result[4] = std::byte{opcode};
    put_u32(result.data() + 5, static_cast<std::uint32_t>(status));
    put_u32(result.data() + 9, static_cast<std::uint32_t>(payload.size()));
    if(!payload.empty())
        std::memcpy(result.data() + header_size, payload.data(), payload.size());
    return result;
}

inline bool decode(const std::vector<std::byte>& data, Header& header,
                   std::string& payload) {
    if(!decode_header(data.data(), data.size(), header)
       || data.size() != header_size + header.payload_size) return false;
    payload.assign(reinterpret_cast<const char*>(data.data() + header_size),
                   header.payload_size);
    return true;
}

} // namespace sx::comm::wire
