#include <gtest/gtest.h>

#include <array>

#include <proxy/socks5/socks5_protocol.hpp>

TEST(Socks5UdpHeader, WaitsForCompleteFixedHeader) {
    const std::array<std::uint8_t, 4> header {0, 0, 0, 1};
    EXPECT_EQ(sx::socks5::inspect_udp_header(nullptr, 0),
              sx::socks5::udp_header_status::incomplete);
    for(std::size_t size = 0; size < header.size(); ++size) {
        EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), size),
                  sx::socks5::udp_header_status::incomplete);
    }
    EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), header.size()),
              sx::socks5::udp_header_status::ready);
}

TEST(Socks5UdpHeader, RejectsNonzeroReservedBytes) {
    for(const auto header : {
            std::array<std::uint8_t, 4>{1, 0, 0, 1},
            std::array<std::uint8_t, 4>{0, 1, 0, 1},
            std::array<std::uint8_t, 4>{0xff, 0xff, 0, 1}}) {
        EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), header.size()),
                  sx::socks5::udp_header_status::invalid_reserved);
    }
}

TEST(Socks5UdpHeader, RejectsUnsupportedFragments) {
    for(const std::uint8_t fragment : {std::uint8_t{1}, std::uint8_t{127},
                                       std::uint8_t{255}}) {
        const std::array<std::uint8_t, 4> header {0, 0, fragment, 1};
        EXPECT_EQ(sx::socks5::inspect_udp_header(header.data(), header.size()),
                  sx::socks5::udp_header_status::fragmented);
    }
}
