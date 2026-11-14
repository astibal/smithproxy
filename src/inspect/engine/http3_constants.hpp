#ifndef SX_HTTP3_CONSTANTS_HPP
#define SX_HTTP3_CONSTANTS_HPP

#include <cstdint>

namespace sx::engine::http::v3::error_code {

// HTTP/3 application error codes (RFC 9114, section 8.1).
// Keep the wire type used by QUIC close/reset APIs, without casts at call sites.
inline constexpr std::uint64_t no_error = 0x100;
inline constexpr std::uint64_t internal_error = 0x102;
inline constexpr std::uint64_t closed_critical_stream = 0x104;
inline constexpr std::uint64_t excessive_load = 0x107;
inline constexpr std::uint64_t request_rejected = 0x10b;
inline constexpr std::uint64_t message_error = 0x10e;

} // namespace sx::engine::http::v3::error_code

namespace sx::engine::http::v3::setting {
inline constexpr std::uint64_t h3_datagram = 0x33; // RFC 9297.
inline constexpr std::uint64_t h3_datagram_draft03 = 0xffd277;
} // namespace sx::engine::http::v3::setting
#endif
