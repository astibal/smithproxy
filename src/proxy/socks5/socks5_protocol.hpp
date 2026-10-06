#pragma once

#include <cstddef>
#include <cstdint>

namespace sx::socks5 {

enum class udp_header_status {
    incomplete,
    ready,
    invalid_reserved,
    fragmented,
};

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

} // namespace sx::socks5
