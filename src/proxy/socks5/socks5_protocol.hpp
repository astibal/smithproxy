#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#include <arpa/inet.h>

namespace sx::socks5 {

constexpr std::size_t maximum_domain_size = 255;
constexpr std::size_t maximum_tcp_reply_size = 4 + 1 + maximum_domain_size + 2;
constexpr std::size_t maximum_socks4_request_size = 1024;

inline std::optional<std::size_t> domain_reply_size(
        std::size_t domain_size) noexcept {
    if(domain_size == 0 || domain_size > maximum_domain_size)
        return std::nullopt;
    return 4 + 1 + domain_size + 2;
}

enum class udp_header_status {
    incomplete,
    ready,
    invalid_reserved,
    fragmented,
};

inline bool offers_no_authentication(const std::uint8_t* methods,
                                     std::size_t count) noexcept {
    if(methods == nullptr) return false;
    for(std::size_t i = 0; i < count; ++i) {
        if(methods[i] == 0) return true;
    }
    return false;
}

inline std::size_t greeting_size_if_complete(const std::uint8_t* data,
                                             std::size_t size) noexcept {
    if(data == nullptr || size < 2) return 0;
    const std::size_t required = 2 + data[1];
    return size >= required ? required : 0;
}

inline bool is_unambiguous_domain(const std::uint8_t* data,
                                  std::size_t size) noexcept {
    if(data == nullptr || size == 0) return false;
    for(std::size_t index = 0; index < size; ++index) {
        // SOCKS carries the name with an explicit length, while resolver and
        // logging consumers do not all share that representation.  Exclude
        // bytes which can create a second textual identity or inject a line.
        if(data[index] <= 0x20U || data[index] == 0x7fU)
            return false;
    }
    return true;
}

inline bool target_setup_succeeded(bool destination_selected,
                                   bool target_prepared) noexcept {
    return destination_selected && target_prepared;
}

inline bool target_port_is_valid(std::uint8_t command,
                                 std::uint16_t port) noexcept {
    // RFC 1928 permits zero only in UDP_ASSOCIATE (command 3), where it
    // describes an as-yet unknown client UDP source port. It is never a
    // usable CONNECT or per-datagram destination.
    return port != 0 || command == 3;
}

inline bool request_version_matches_negotiation(
        std::uint8_t negotiated_version,
        std::uint8_t request_version) noexcept {
    // SOCKS4 has no separate method-negotiation phase.  A completed SOCKS5
    // greeting, however, binds every following request to version 5.
    return negotiated_version != 5 || request_version == 5;
}

inline void store_network_u16(std::uint8_t* destination,
                              std::uint16_t host_value) noexcept {
    if(destination == nullptr) return;
    const auto network_value = htons(host_value);
    std::memcpy(destination, &network_value, sizeof(network_value));
}

inline void store_network_u32(std::uint8_t* destination,
                              std::uint32_t network_value) noexcept {
    if(destination == nullptr) return;
    std::memcpy(destination, &network_value, sizeof(network_value));
}

inline std::uint16_t sockaddr_port(std::uint16_t host_value) noexcept {
    return htons(host_value);
}

inline bool udp_relay_endpoint_ready(
        bool resolved, std::optional<std::uint16_t> port) noexcept {
    return resolved && port.has_value();
}

inline bool pollable_control_socket(int descriptor) noexcept {
    // This is specifically the TCP control channel passed to poll/recv, not a
    // synthetic transport identity. Descriptor zero is valid when stdin was
    // closed before accept/socket allocation.
    return descriptor >= 0;
}

inline std::size_t request_size_if_complete(const std::uint8_t* data,
                                            std::size_t size) noexcept {
    if(data == nullptr || size < 4) return 0;
    switch(data[3]) {
        case 1: // IPv4
            return size >= 10 ? 10 : 0;
        case 4: // IPv6
            return size >= 22 ? 22 : 0;
        case 3: { // domain
            if(size < 5) return 0;
            const std::size_t required = 7 + data[4];
            return size >= required ? required : 0;
        }
        default:
            // Four bytes are sufficient for the caller to reject ATYP.
            return 4;
    }
}

inline bool is_socks4a(const std::uint8_t* data, std::size_t size) noexcept {
    return data != nullptr && size >= 8 && data[4] == 0 && data[5] == 0 &&
           data[6] == 0 && data[7] != 0;
}

inline std::size_t socks4_request_size_if_complete(
        const std::uint8_t* data, std::size_t size) noexcept {
    if(data == nullptr || size < 9) return 0;
    auto const* user_end = static_cast<const std::uint8_t*>(
        std::memchr(data + 8, 0, size - 8));
    if(user_end == nullptr) return 0;
    if(!is_socks4a(data, size))
        return static_cast<std::size_t>(user_end - data) + 1;

    auto const domain_offset = static_cast<std::size_t>(user_end - data) + 1;
    if(domain_offset >= size) return 0;
    auto const* domain_end = static_cast<const std::uint8_t*>(
        std::memchr(data + domain_offset, 0, size - domain_offset));
    if(domain_end == nullptr) return 0;
    return static_cast<std::size_t>(domain_end - data) + 1;
}

inline std::size_t initial_frame_size_if_complete(
        const std::uint8_t* data, std::size_t size) noexcept {
    if(data == nullptr || size == 0) return 0;
    if(data[0] == 4) {
        const auto frame = socks4_request_size_if_complete(data, size);
        if(frame == 0 && size >= maximum_socks4_request_size)
            return maximum_socks4_request_size;
        return frame;
    }
    if(data[0] == 5)
        return greeting_size_if_complete(data, size);
    // One byte is sufficient for the caller to reject an unknown version.
    // Do not reinterpret its second byte as SOCKS5's NMETHODS length.
    return 1;
}

inline std::optional<std::string_view> socks4a_domain(
        const std::uint8_t* data, std::size_t request_size) noexcept {
    if(!is_socks4a(data, request_size)) return std::nullopt;
    auto const* user_end = static_cast<const std::uint8_t*>(
        std::memchr(data + 8, 0, request_size - 8));
    if(user_end == nullptr) return std::nullopt;
    auto const* domain = user_end + 1;
    if(domain >= data + request_size) return std::nullopt;
    auto const* domain_end = static_cast<const std::uint8_t*>(
        std::memchr(domain, 0, static_cast<std::size_t>(data + request_size - domain)));
    if(domain_end == nullptr || domain_end == domain) return std::nullopt;
    if(!is_unambiguous_domain(
           domain, static_cast<std::size_t>(domain_end - domain)))
        return std::nullopt;
    return std::string_view(reinterpret_cast<const char*>(domain),
                            static_cast<std::size_t>(domain_end - domain));
}

inline udp_header_status inspect_udp_header(const std::uint8_t* data,
                                            std::size_t size) noexcept {
    if(data == nullptr || size < 4)
        return udp_header_status::incomplete;
    if(data[0] != 0 || data[1] != 0)
        return udp_header_status::invalid_reserved;
    // RFC 1928 fragmentation is optional. Smithproxy does not implement the
    // reassembly queue, so accepting FRAG != 0 would forward incomplete
    // application datagrams as if they were whole.
    if(data[2] != 0)
        return udp_header_status::fragmented;
    return udp_header_status::ready;
}

namespace detail {
template<typename Frontend>
bool udp_handoff_endpoints_ready(Frontend const* frontend) noexcept {
    return frontend != nullptr && frontend->left && frontend->right;
}
} // namespace detail

} // namespace sx::socks5
