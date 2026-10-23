#include <gtest/gtest.h>

#include "proxy/quic/spq1.hpp"

#include <traflog/pcapapi.hpp>
#include <traflog/pcaplog.hpp>
#include <algorithm>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace {

struct captured_packet {
    socle::side_t side;
    std::vector<unsigned char> data;
};

struct captured_secret {
    socle::traffic_secret_format format;
    std::vector<unsigned char> data;
};

class capture_sink final : public socle::baseTrafficLogger {
public:
    explicit capture_sink(
        std::shared_ptr<std::vector<captured_packet>> packets,
        std::shared_ptr<std::vector<captured_packet>> native_packets = {},
        std::shared_ptr<std::vector<captured_secret>> secrets = {},
        std::shared_ptr<std::vector<std::string>> events = {})
        : packets_(std::move(packets)), native_packets_(std::move(native_packets)),
          secrets_(std::move(secrets)), events_(std::move(events)) {}

    void write(socle::side_t side, buffer const& data) override {
        auto const* begin = static_cast<unsigned char const*>(data.data());
        packets_->push_back({side, {begin, begin + data.size()}});
    }
    void write(socle::side_t, std::string const&) override {}
    void write_packet(socle::side_t side, buffer const& data) override {
        if (!native_packets_) return;
        if (events_) events_->push_back("packet");
        auto const* begin = static_cast<unsigned char const*>(data.data());
        native_packets_->push_back({side, {begin, begin + data.size()}});
    }
    void write_secret(socle::traffic_secret_format format,
                      buffer const& data) override {
        if (!secrets_) return;
        if (events_) events_->push_back("secret");
        auto const* begin = static_cast<unsigned char const*>(data.data());
        secrets_->push_back({format, {begin, begin + data.size()}});
    }

private:
    std::shared_ptr<std::vector<captured_packet>> packets_;
    std::shared_ptr<std::vector<captured_packet>> native_packets_;
    std::shared_ptr<std::vector<captured_secret>> secrets_;
    std::shared_ptr<std::vector<std::string>> events_;
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

TEST(Spq1, ConvertsInitialH3RequestHeadersToFlowObservations) {
    sx::quic::h3_headers_record request {
        socle::side_t::LEFT,
        4,
        {{":method", "GET"}, {":scheme", "https"},
         {":authority", "video.example"}, {":path", "/watch?id=7"}},
    };

    auto const fields = sx::quic::spq1::h3_flow_observations(request);
    EXPECT_EQ("true", fields.at("flow.http3"));
    EXPECT_EQ("GET", fields.at("flow.http3.method"));
    EXPECT_EQ("https", fields.at("flow.http3.scheme"));
    EXPECT_EQ("video.example", fields.at("flow.http3.authority"));
    EXPECT_EQ("/watch?id=7", fields.at("flow.http3.path"));
    EXPECT_EQ("https://video.example/watch?id=7", fields.at("flow.http3.url"));

    request.side = socle::side_t::RIGHT;
    EXPECT_TRUE(sx::quic::spq1::h3_flow_observations(request).empty());
    request.side = socle::side_t::LEFT;
    request.fields = {{":method", "POST"}, {":scheme", "https"},
                      {":authority", "resolver.example"}, {":path", "/dns-query"},
                      {"content-type", "application/dns-message"},
                      {"accept", "application/dns-message"}};
    auto const doh = sx::quic::spq1::h3_flow_observations(request);
    EXPECT_EQ("application/dns-message", doh.at("flow.http3.content_type"));
    EXPECT_EQ("application/dns-message", doh.at("flow.http3.accept"));
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

TEST(Spq1, ForwardsNativePacketsAndSecretsWithoutTransformation) {
    auto packets = std::make_shared<std::vector<captured_packet>>();
    auto native_packets = std::make_shared<std::vector<captured_packet>>();
    auto secrets = std::make_shared<std::vector<captured_secret>>();
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(8, "h3");
    auto sink = std::make_unique<capture_sink>(packets, native_packets, secrets);
    sx::quic::spq1::stream_log log(std::move(sink), {connection, 4});
    std::string const packet = "complete-native-packet";
    std::string const keylog = "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00 aa";
    buffer packet_data(packet.data(), packet.size());
    buffer secret_data(keylog.data(), keylog.size());

    log.write_packet(socle::side_t::LEFT, packet_data);
    log.write_secret(socle::traffic_secret_format::tls_key_log, secret_data);

    EXPECT_TRUE(packets->empty());
    ASSERT_EQ(native_packets->size(), 1U);
    EXPECT_EQ(std::string(native_packets->front().data.begin(),
                          native_packets->front().data.end()), packet);
    ASSERT_EQ(secrets->size(), 1U);
    EXPECT_EQ(secrets->front().format, socle::traffic_secret_format::tls_key_log);
    EXPECT_EQ(std::string(secrets->front().data.begin(), secrets->front().data.end()),
              keylog);
}

TEST(SessionTrafficLog, ReplaysPrePolicyRecordsAndThenWritesDirectly) {
    auto packets = std::make_shared<std::vector<captured_packet>>();
    auto native_packets = std::make_shared<std::vector<captured_packet>>();
    auto secrets = std::make_shared<std::vector<captured_secret>>();
    auto events = std::make_shared<std::vector<std::string>>();
    auto journal = std::make_shared<sx::session_traffic_log>(1024);
    std::string const first = "first-wire-packet";
    std::string const key = "CLIENT_TRAFFIC_SECRET_0 00 aa";
    std::string const second = "second-wire-packet";

    buffer first_data(first.data(), first.size());
    buffer key_data(key.data(), key.size());
    journal->write_packet(socle::side_t::LEFT, first_data);
    journal->write_secret(socle::traffic_secret_format::tls_key_log, key_data);
    EXPECT_GT(journal->pending_bytes(), 0U);

    auto output = std::make_shared<capture_sink>(packets, native_packets, secrets, events);
    ASSERT_TRUE(journal->install(output));
    EXPECT_EQ(journal->pending_bytes(), 0U);
    buffer second_data(second.data(), second.size());
    journal->write_packet(socle::side_t::RIGHT, second_data);

    ASSERT_EQ(native_packets->size(), 2U);
    EXPECT_EQ(std::string(native_packets->at(0).data.begin(),
                          native_packets->at(0).data.end()), first);
    EXPECT_EQ(native_packets->at(1).side, socle::side_t::RIGHT);
    EXPECT_EQ(std::string(native_packets->at(1).data.begin(),
                          native_packets->at(1).data.end()), second);
    ASSERT_EQ(secrets->size(), 1U);
    EXPECT_EQ(std::string(secrets->front().data.begin(), secrets->front().data.end()), key);
    EXPECT_EQ(*events, (std::vector<std::string> {"secret", "packet", "packet"}));
    EXPECT_FALSE(journal->install(output));
}

TEST(SessionTrafficLog, SecretsEvictPacketsAtTheBound) {
    auto packets = std::make_shared<std::vector<captured_packet>>();
    auto native_packets = std::make_shared<std::vector<captured_packet>>();
    auto secrets = std::make_shared<std::vector<captured_secret>>();
    sx::session_traffic_log journal(8);
    std::string const packet = "12345678";
    std::string const key = "secret";
    buffer packet_data(packet.data(), packet.size());
    buffer key_data(key.data(), key.size());

    journal.write_packet(socle::side_t::LEFT, packet_data);
    journal.write_secret(socle::traffic_secret_format::tls_key_log, key_data);
    ASSERT_TRUE(journal.install(
        std::make_shared<capture_sink>(packets, native_packets, secrets)));

    EXPECT_TRUE(native_packets->empty());
    ASSERT_EQ(secrets->size(), 1U);
    EXPECT_EQ(journal.dropped_records(), 1U);
}

TEST(SessionTrafficLog, SerializesConcurrentPublishers) {
    auto packets = std::make_shared<std::vector<captured_packet>>();
    auto native_packets = std::make_shared<std::vector<captured_packet>>();
    sx::session_traffic_log journal(1024);
    ASSERT_TRUE(journal.install(std::make_shared<capture_sink>(packets, native_packets)));

    std::vector<std::thread> writers;
    for (unsigned char writer = 0; writer < 4; ++writer) {
        writers.emplace_back([&journal, writer]() {
            for (std::size_t item = 0; item < 100; ++item) {
                unsigned char payload[] {writer, static_cast<unsigned char>(item)};
                buffer packet(payload, sizeof(payload));
                journal.write_packet(socle::side_t::LEFT, packet);
            }
        });
    }
    for (auto& writer : writers) writer.join();

    EXPECT_EQ(native_packets->size(), 400U);
    EXPECT_EQ(journal.dropped_records(), 0U);
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

TEST(Spq1, AdapterLeavesStreamLoggerUnchanged) {
    auto packets = std::make_shared<std::vector<captured_packet>>();
    auto output = std::make_unique<capture_sink>(packets);
    auto* original = output.get();
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(8, "h3");
    sx::quic::spq1::stream_log_adapter adapter({connection, 4});

    auto wrapped = adapter.wrap(std::move(output));

    EXPECT_EQ(original, wrapped.get());
}

TEST(Spq1, AdapterConfiguresAndWrapsPacketLogger) {
    auto output = std::make_unique<socle::traflog::PcapLog>(
        nullptr, "/tmp", "spq1-adapter-test", ".pcap", false);
    auto* pcap = output.get();
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(
        0x1122334455667788ULL, "h3");
    sx::quic::spq1::stream_log_adapter adapter({connection, 12});

    auto wrapped = adapter.wrap(std::move(output));

    EXPECT_NE(pcap, wrapped.get());
    EXPECT_EQ(socle::pcap::connection_details::UDP, pcap->details.next_proto);
    ASSERT_TRUE(pcap->details.gre_key.has_value());
    EXPECT_EQ(0x55667788U, *pcap->details.gre_key);
}

TEST(Spq1, AdapterDescribesHttp3DataFrames) {
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(9, "h3");
    sx::quic::spq1::stream_log_adapter adapter({connection, 0});
    unsigned char bytes[] {0x01, 0x00, 0x00, 0x03, 'a', 'b', 'c',
                           0x21, 0x01, 'x', 0x00, 0x02, 'd', 'e'};
    buffer data(bytes, sizeof(bytes));

    auto metadata = adapter.inspect_content(socle::side_t::LEFT, data);

    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ("http3", metadata->payload_layer);
    ASSERT_EQ(2U, metadata->payload_ranges.size());
    EXPECT_EQ((std::pair<std::int64_t, std::int64_t>{4, 7}),
              metadata->payload_ranges[0]);
    EXPECT_EQ((std::pair<std::int64_t, std::int64_t>{12, 14}),
              metadata->payload_ranges[1]);
    EXPECT_EQ((std::vector<std::string>{"", ""}), metadata->encodings);
}

TEST(Spq1, AdapterTracksHttp3DataAcrossContentMessages) {
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(10, "h3");
    sx::quic::spq1::stream_log_adapter adapter({connection, 0});
    unsigned char first_bytes[] {0x00, 0x05, 'a', 'b'};
    unsigned char second_bytes[] {'c', 'd', 'e', 0x01, 0x00};
    buffer first(first_bytes, sizeof(first_bytes));
    buffer second(second_bytes, sizeof(second_bytes));

    auto first_metadata = adapter.inspect_content(socle::side_t::LEFT, first);
    auto second_metadata = adapter.inspect_content(socle::side_t::LEFT, second);

    ASSERT_TRUE(first_metadata.has_value());
    ASSERT_TRUE(second_metadata.has_value());
    EXPECT_EQ((std::vector<std::pair<std::int64_t, std::int64_t>>{{2, 4}}),
              first_metadata->payload_ranges);
    EXPECT_EQ((std::vector<std::pair<std::int64_t, std::int64_t>>{{0, 3}}),
              second_metadata->payload_ranges);
}

TEST(Spq1, AdapterAlignsHttp3ContentEncodingWithDataRanges) {
    auto connection = std::make_shared<sx::quic::spq1::connection_context>(11, "h3");
    connection->content_encoding(socle::side_t::RIGHT, 0, "gzip");
    sx::quic::spq1::stream_log_adapter adapter({connection, 0});
    unsigned char bytes[] {0x00, 0x01, 'a', 0x00, 0x01, 'b'};
    buffer data(bytes, sizeof(bytes));

    auto metadata = adapter.inspect_content(socle::side_t::RIGHT, data);

    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ((std::vector<std::string>{"gzip", "gzip"}), metadata->encodings);
}
