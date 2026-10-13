#include "../inspect/engine/http.hpp"
#include "../../proxy/content_webhook_metadata.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace {

using sx::engine::http::L7PayloadHints;
using sx::engine::http::v2::Http2Direction;

std::string frame(std::uint8_t type, std::uint8_t flags,
                  std::uint32_t stream, std::string_view payload) {
    std::string out(9, '\0');
    out[0] = static_cast<char>((payload.size() >> 16U) & 0xffU);
    out[1] = static_cast<char>((payload.size() >> 8U) & 0xffU);
    out[2] = static_cast<char>(payload.size() & 0xffU);
    out[3] = static_cast<char>(type);
    out[4] = static_cast<char>(flags);
    out[5] = static_cast<char>((stream >> 24U) & 0x7fU);
    out[6] = static_cast<char>((stream >> 16U) & 0xffU);
    out[7] = static_cast<char>((stream >> 8U) & 0xffU);
    out[8] = static_cast<char>(stream & 0xffU);
    out.append(payload);
    return out;
}

struct Observation {
    std::string body;
    bool unknown = false;
};

Observation observe(std::string_view wire, std::vector<std::size_t> cuts,
                    bool client_side = false) {
    cuts.push_back(0);
    cuts.push_back(wire.size());
    std::sort(cuts.begin(), cuts.end());
    cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
    Http2Direction direction;
    Observation result;
    for(std::size_t part = 1; part < cuts.size(); ++part) {
        const auto block = wire.substr(cuts[part - 1], cuts[part] - cuts[part - 1]);
        if(block.empty()) continue;
        const auto ranges = direction.observe(block, client_side);
        std::int64_t previous = 0;
        for(const auto [start, end] : ranges) {
            if(start == -1 && end == -1) {
                result.unknown = true;
                continue;
            }
            if(start == 0 && end == 0) continue;
            EXPECT_GE(start, previous);
            EXPECT_GE(end, start);
            EXPECT_LE(static_cast<std::size_t>(end), block.size());
            if(start >= 0 && end >= start && static_cast<std::size_t>(end) <= block.size())
                result.body.append(block.substr(static_cast<std::size_t>(start),
                                                static_cast<std::size_t>(end - start)));
            previous = end;
        }
    }
    return result;
}

void every_single_split(std::string_view wire, std::string_view body,
                        bool client_side = false) {
    for(std::size_t split = 0; split <= wire.size(); ++split) {
        SCOPED_TRACE(split);
        const auto result = observe(wire, {split}, client_side);
        EXPECT_FALSE(result.unknown);
        EXPECT_EQ(result.body, body);
    }
}

} // namespace

TEST(Http2ContentFraming, DataSurvivesEverySingleSplit) {
    every_single_split(frame(0, 0, 1, "hello world"), "hello world");
}

TEST(Http2ContentFraming, ClientPrefaceAndDataSurviveEverySingleSplit) {
    const std::string wire = std::string(sx::engine::http::v2::txt::magic) +
                             frame(4, 0, 0, {}) + frame(0, 1, 1, "body");
    every_single_split(wire, "body", true);
}

TEST(Http2ContentFraming, DataSurvivesEveryDoubleSplit) {
    const std::string wire = frame(1, 4, 1, "headers") +
                             frame(0, 0, 1, "abcdef") +
                             frame(6, 0, 0, "12345678");
    for(std::size_t first = 0; first <= wire.size(); ++first) {
        for(std::size_t second = first; second <= wire.size(); ++second) {
            SCOPED_TRACE(::testing::Message() << first << ',' << second);
            const auto result = observe(wire, {first, second});
            EXPECT_FALSE(result.unknown);
            EXPECT_EQ(result.body, "abcdef");
        }
    }
}

TEST(Http2ContentFraming, PaddedDataExcludesLengthAndPadding) {
    const std::string payload("\x03hello\0\0\0", 9);
    every_single_split(frame(0, 0x08, 1, payload), "hello");
}

TEST(Http2ContentFraming, MultipleDataFramesProduceOnlyData) {
    const std::string wire = frame(0, 0, 1, "one") + frame(4, 0, 0, {}) +
                             frame(0, 1, 3, "two");
    every_single_split(wire, "onetwo");
}

TEST(Http2ContentFraming, ZeroLengthAndControlFramesHaveNoPayload) {
    Http2Direction direction;
    EXPECT_EQ(direction.observe(frame(0, 1, 1, {}), false),
              L7PayloadHints({{0, 0}}));
    EXPECT_EQ(direction.observe(frame(4, 0, 0, "settings"), false),
              L7PayloadHints({{0, 0}}));
}

TEST(Http2ContentFraming, InvalidPaddingFailsClosedAndStaysClosed) {
    Http2Direction direction;
    const std::string invalid_payload("\x05x", 2);
    EXPECT_EQ(direction.observe(frame(0, 0x08, 1, invalid_payload), false),
              L7PayloadHints({{-1, -1}}));
    EXPECT_EQ(direction.observe(frame(0, 0, 1, "later"), false),
              L7PayloadHints({{-1, -1}}));
}

TEST(Http2ContentFraming, WebhookIndicesReferToExactCurrentBlock) {
    Http2Direction direction;
    const auto wire = frame(0, 0, 1, "abcdefghij");
    const auto split = 12U; // header plus first three DATA bytes
    const auto first = std::string_view(wire).substr(0, split);
    const auto second = std::string_view(wire).substr(split);

    auto ranges = direction.observe(first, false);
    auto metadata = sx::proxy::l7_payload_metadata(ranges, {});
    EXPECT_EQ(metadata["L7_payload_start"], nlohmann::json::array({9}));
    EXPECT_EQ(metadata["L7_payload_end"], nlohmann::json::array({12}));
    EXPECT_EQ(first.substr(9, 3), "abc");

    ranges = direction.observe(second, false);
    metadata = sx::proxy::l7_payload_metadata(ranges, {});
    EXPECT_EQ(metadata["L7_payload_start"], nlohmann::json::array({0}));
    EXPECT_EQ(metadata["L7_payload_end"], nlohmann::json::array({7}));
    EXPECT_EQ(second.substr(0, 7), "defghij");
    EXPECT_EQ(nlohmann::json::parse(metadata.dump()), metadata);
}

TEST(Http2ContentFraming, EnginePublishesPerRangeEncodingToWebhookMetadata) {
    sx::engine::EngineCtx ctx;
    auto app = std::make_shared<sx::engine::http::app_HttpRequest>();
    app->version = sx::engine::http::app_HttpRequest::HTTP_VER::HTTP2;
    ctx.application_data = app;
    ctx.state_data = std::make_any<sx::engine::http::v2::Http2Connection>();
    auto* connection = std::any_cast<sx::engine::http::v2::Http2Connection>(
        &ctx.state_data);
    ASSERT_NE(connection, nullptr);
    connection->streams[1].content_encoding_ =
        sx::engine::http::v2::Http2Stream::content_type_t::GZIP;
    connection->streams[3].content_encoding_ =
        sx::engine::http::v2::Http2Stream::content_type_t::PLAIN;

    const auto wire = frame(0, 0, 1, "compressed") +
                      frame(0, 0, 3, "plain");
    sx::engine::http::v2::observe_content(ctx, 1, wire, 1234, false);
    ASSERT_TRUE(app->l7_payload_matches(wire, 1234));
    const auto metadata = sx::proxy::l7_payload_metadata(
        app->l7_payload, app->l7_encoding);
    EXPECT_EQ(metadata["L7_payload_start"], nlohmann::json::array({9, 28}));
    EXPECT_EQ(metadata["L7_payload_end"], nlohmann::json::array({19, 33}));
    EXPECT_EQ(metadata["L7_encoding"], nlohmann::json::array({"gzip", ""}));
}

TEST(Http2ContentFraming, DeterministicRandomSegmentationPreservesPayload) {
    std::string body(65536, '\0');
    for(std::size_t i = 0; i < body.size(); ++i) body[i] = static_cast<char>(i);
    const auto wire = frame(1, 4, 1, "h") + frame(0, 1, 1, body);
    std::mt19937 random(0x48324652U);
    std::uniform_int_distribution<std::size_t> cut(0, wire.size());
    for(std::size_t iteration = 0; iteration < 500; ++iteration) {
        std::vector<std::size_t> cuts;
        for(std::size_t i = 0; i < 32; ++i) cuts.push_back(cut(random));
        const auto result = observe(wire, std::move(cuts));
        ASSERT_FALSE(result.unknown);
        ASSERT_EQ(result.body, body);
    }
}
