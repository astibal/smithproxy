#include <gtest/gtest.h>

#include "proxy/quic/spq1.hpp"

#include <traflog/pcapapi.hpp>
#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

namespace {

struct captured_packet {
    socle::side_t side;
    std::vector<unsigned char> data;
};

class capture_sink final : public socle::baseTrafficLogger {
public:
    explicit capture_sink(std::shared_ptr<std::vector<captured_packet>> packets)
        : packets_(std::move(packets)) {}

    void write(socle::side_t side, buffer const& data) override {
        auto const* begin = static_cast<unsigned char const*>(data.data());
        packets_->push_back({side, {begin, begin + data.size()}});
    }
    void write(socle::side_t, std::string const&) override {}

private:
    std::shared_ptr<std::vector<captured_packet>> packets_;
};

} // namespace

TEST(Spq1, EncodesSelfContainedStreamPacket) {
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(2, "h3");
    sx::quic::spq1::stream_context stream {connection, 0};
    unsigned char const plaintext[] {'h', 'e', 'l', 'l', 'o'};

    auto const packet = sx::quic::spq1::encode_stream_packet(
        stream, 45, plaintext, sizeof(plaintext), false);

    ASSERT_EQ(35U, packet.size());
    EXPECT_EQ(0xD3, packet[0]);
    EXPECT_EQ("SPQ1", std::string(packet.begin() + 1, packet.begin() + 5));
    EXPECT_EQ(8, packet[5]);
    EXPECT_EQ(2, packet[13]);
    EXPECT_EQ(0, packet[14]);
    EXPECT_EQ(19, packet[15]);
    EXPECT_EQ(1, packet[19]);
    EXPECT_EQ(2, packet[20]);
    EXPECT_EQ("h3", std::string(packet.begin() + 21, packet.begin() + 23));
    EXPECT_EQ(0x0E, packet[23]);
    EXPECT_EQ(0, packet[24]);
    EXPECT_EQ(45, packet[25]);
    EXPECT_EQ(5, packet[26]);
    EXPECT_EQ(">>>", std::string(packet.begin() + 27, packet.begin() + 30));
    EXPECT_EQ("hello", std::string(packet.begin() + 30, packet.end()));
}

TEST(Spq1, EncodesDecodedH3HeadersAsPrivateExtension) {
    sx::quic::spq1::connection_context connection(9, "h3");
    sx::quic::h3_headers_record record {
        socle::side_t::LEFT,
        4,
        {{":method", "GET"}, {":path", "/demo"}},
    };

    auto const packet = sx::quic::spq1::encode_h3_headers_packet(
        connection, record);
    std::vector<unsigned char> const extension_type {0x80, 0x00, 0xFA, 0xCE};
    EXPECT_NE(packet.end(), std::search(
        packet.begin(), packet.end(), extension_type.begin(), extension_type.end()));
    EXPECT_NE(packet.end(), std::search(
        packet.begin(), packet.end(), record.fields[0].name.begin(),
        record.fields[0].name.end()));
    EXPECT_EQ(">>>", std::string(packet.end() - 3, packet.end()));
}

TEST(Spq1, SplitsGreSafeChunksAndEmitsOneFin) {
    auto packets = std::make_shared<std::vector<captured_packet>>();
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(7, "h3");
    std::vector<unsigned char> plaintext(1101, 0xA5);

    {
        auto sink = std::make_unique<capture_sink>(packets);
        sx::quic::spq1::stream_log log(
            std::move(sink), {connection, 12});
        buffer data(plaintext.data(), plaintext.size());
        log.write(socle::side_t::LEFT, data);
        log.finish(socle::side_t::LEFT);
        log.finish(socle::side_t::LEFT);
    }

    ASSERT_EQ(3U, packets->size());
    EXPECT_TRUE(std::all_of(packets->begin(), packets->end(), [](auto const& packet) {
        return packet.side == socle::side_t::LEFT
            && packet.data.size() > 5
            && std::string(packet.data.begin() + 1, packet.data.begin() + 5) == "SPQ1";
    }));
    EXPECT_NE(0, packets->back().data[23] & 0x01);
}

TEST(Spq1, DisabledCaptureDoesNotLeakDestructorFin) {
    auto packets = std::make_shared<std::vector<captured_packet>>();
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(8, "h3");
    {
        auto sink = std::make_unique<capture_sink>(packets);
        sx::quic::spq1::stream_log log(std::move(sink), {connection, 4});
        std::string const plaintext = "observed before capture shutdown";
        buffer data(plaintext.data(), plaintext.size());
        log.write(socle::side_t::LEFT, data);
        ASSERT_EQ(1U, packets->size());
        log.status(false);
    }

    EXPECT_EQ(1U, packets->size());
}

TEST(Spq1, GreKeyCarriesLowSessionIdentifier) {
    socle::pcap::connection_details details;
    details.ip_version = 4;
    details.gre_key = 0x01020304;
    buffer header;

    socle::pcapng::append_GRE_header(header, details);

    ASSERT_EQ(8U, header.size());
    auto const* bytes = static_cast<unsigned char const*>(header.data());
    EXPECT_EQ(0x20, bytes[0]);
    EXPECT_EQ(0x00, bytes[1]);
    EXPECT_EQ(0x08, bytes[2]);
    EXPECT_EQ(0x00, bytes[3]);
    EXPECT_EQ(0x01, bytes[4]);
    EXPECT_EQ(0x02, bytes[5]);
    EXPECT_EQ(0x03, bytes[6]);
    EXPECT_EQ(0x04, bytes[7]);
}
