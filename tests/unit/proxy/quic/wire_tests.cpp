#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "proxy/quic/wire.hpp"

namespace quic = sx::quic;

TEST(QuicVarint, ParsesAllEncodedSizes) {
    std::array<std::uint8_t, 1> one { 37 };
    std::array<std::uint8_t, 2> two { 0x7b, 0xbd }; // 15293
    std::array<std::uint8_t, 4> four { 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    std::array<std::uint8_t, 8> eight { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };

    EXPECT_EQ(quic::parse_varint(one.data(), one.size()).value, 37U);
    EXPECT_EQ(quic::parse_varint(two.data(), two.size()).value, 15293U);
    EXPECT_EQ(quic::parse_varint(four.data(), four.size()).value, 494878333U);
    EXPECT_EQ(quic::parse_varint(eight.data(), eight.size()).value, 151288809941952652ULL);
}

TEST(QuicWire, ParsesVersionOneInitialPrefix) {
    // Long header, QUIC v1, 8-byte DCID, empty SCID, empty token,
    // protected payload length 4 and four opaque protected bytes.
    std::vector<std::uint8_t> packet {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x00,
        0x00,
        0x04,
        0xaa, 0xbb, 0xcc, 0xdd,
    };

    auto const result = quic::parse_header(packet);
    ASSERT_TRUE(result) << quic::to_string(result.error);
    EXPECT_EQ(result.value.form, quic::packet_form::long_header);
    EXPECT_EQ(result.value.type, quic::packet_type::initial);
    EXPECT_EQ(result.value.version, quic::version_1);
    EXPECT_EQ(result.value.destination_connection_id.size(), 8U);
    EXPECT_TRUE(result.value.source_connection_id.empty());
    ASSERT_TRUE(result.value.protected_payload_length);
    EXPECT_EQ(*result.value.protected_payload_length, 4U);
    EXPECT_EQ(result.value.packet_end, packet.size());
}

TEST(QuicWire, UsesVersionTwoPacketTypeMapping) {
    std::vector<std::uint8_t> packet {
        0xd0, 0x6b, 0x33, 0x43, 0xcf,
        0x00, 0x00, // empty DCID and SCID
        0x00,       // empty token
        0x01, 0xaa, // one protected byte
    };

    auto const result = quic::parse_header(packet);
    ASSERT_TRUE(result) << quic::to_string(result.error);
    EXPECT_EQ(result.value.type, quic::packet_type::initial);
    EXPECT_EQ(result.value.version, quic::version_2);
}

TEST(QuicWire, ParsesVersionNegotiationWithoutFixedBit) {
    std::vector<std::uint8_t> packet {
        0x80, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x01, 0x02, 0x03, 0x04,
        0x02, 0xaa, 0xbb,
        0x00, 0x00, 0x00, 0x01,
    };

    auto const result = quic::parse_header(packet);
    ASSERT_TRUE(result) << quic::to_string(result.error);
    EXPECT_EQ(result.value.type, quic::packet_type::version_negotiation);
    EXPECT_EQ(result.value.destination_connection_id.size(), 4U);
    EXPECT_EQ(result.value.source_connection_id.size(), 2U);
}

TEST(QuicWire, RejectsMalformedVersionNegotiationLists) {
    for(auto const& versions : std::vector<std::vector<std::uint8_t>>{
            {}, {0x00}, {0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x01, 0xff}}) {
        std::vector<std::uint8_t> packet {
            0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // empty DCID and SCID
        };
        packet.insert(packet.end(), versions.begin(), versions.end());
        EXPECT_EQ(quic::parse_header(packet).error,
                  quic::parse_error::invalid_length);
    }

    std::vector<std::uint8_t> two_versions {
        0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x6b, 0x33, 0x43, 0xcf,
    };
    EXPECT_TRUE(quic::parse_header(two_versions));

    std::vector<std::uint8_t> reserved_zero_version {
        0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    EXPECT_EQ(quic::parse_header(reserved_zero_version).error,
              quic::parse_error::invalid_length);
}

TEST(QuicWire, RequiresTheRetryIntegrityTag) {
    std::vector<std::uint8_t> retry {
        0xf0, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, // empty DCID and SCID
    };
    for(std::size_t size = 0; size < 16; ++size) {
        retry.push_back(0xaa);
        EXPECT_EQ(quic::parse_header(retry).error,
                  size == 15 ? quic::parse_error::none
                             : quic::parse_error::truncated);
    }
}

TEST(QuicWire, RejectsAZeroProtectedPayloadLength) {
    for(auto first_byte: {std::uint8_t{0xc0}, std::uint8_t{0xd0},
                          std::uint8_t{0xe0}}) {
        std::vector<std::uint8_t> packet {
            first_byte, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, // empty DCID and SCID
        };
        if(first_byte == 0xc0)
            packet.push_back(0x00); // empty Initial token
        packet.push_back(0x00); // impossible Length: no packet-number byte
        EXPECT_EQ(quic::parse_header(packet).error,
                  quic::parse_error::invalid_length);
    }
}

TEST(QuicWire, UnsupportedVersionStillRequiresPacketData) {
    std::vector<std::uint8_t> invariant_prefix {
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        0x00, 0x00, // empty DCID and SCID
    };
    auto const incomplete = quic::parse_header(invariant_prefix);
    EXPECT_EQ(incomplete.error, quic::parse_error::truncated);
    EXPECT_EQ(incomplete.error_offset, invariant_prefix.size());

    invariant_prefix.push_back(0xaa);
    auto const complete = quic::parse_header(invariant_prefix);
    ASSERT_TRUE(complete) << quic::to_string(complete.error);
    EXPECT_EQ(complete.value.type, quic::packet_type::unknown);
    EXPECT_EQ(complete.value.packet_end, invariant_prefix.size());
}

TEST(QuicWire, RejectsInvalidAndTruncatedPackets) {
    std::vector<std::uint8_t> udp_payload { 0x01, 0x02, 0x03 };
    EXPECT_EQ(quic::parse_header(udp_payload).error, quic::parse_error::not_quic);

    std::vector<std::uint8_t> long_header { 0xc0, 0x00, 0x00 };
    EXPECT_EQ(quic::parse_header(long_header).error, quic::parse_error::truncated);

    std::vector<std::uint8_t> invalid_cid {
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x15,
    };
    EXPECT_EQ(quic::parse_header(invalid_cid).error, quic::parse_error::invalid_connection_id);

    const std::array<std::uint8_t, 1> empty_short_header {0x40};
    EXPECT_EQ(quic::parse_header(empty_short_header.data(),
                                 empty_short_header.size()).error,
              quic::parse_error::truncated);
    const std::array<std::uint8_t, 2> minimal_short_header {0x40, 0x00};
    EXPECT_TRUE(quic::parse_header(minimal_short_header.data(),
                                   minimal_short_header.size()));
}
