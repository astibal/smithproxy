#include "../engine.hpp"
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
using sx::engine::http::v1::Http1Connection;
using sx::engine::http::v1::Http1Direction;

struct Observation {
    std::string body;
    std::vector<std::string> encodings;
    bool unknown = false;
};

Observation observe_segments(std::string_view wire,
                             std::vector<std::size_t> cuts,
                             bool response_side) {
    cuts.push_back(0);
    cuts.push_back(wire.size());
    std::sort(cuts.begin(), cuts.end());
    cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());

    Http1Direction direction;
    Observation result;
    for(std::size_t part = 1; part < cuts.size(); ++part) {
        const auto begin = cuts[part - 1];
        const auto end = cuts[part];
        if(begin == end) continue;
        const auto block = wire.substr(begin, end - begin);
        const auto ranges = direction.observe(block, response_side);
        const auto& encodings = direction.encodings();

        EXPECT_FALSE(ranges.empty());
        EXPECT_TRUE(encodings.size() == ranges.size());
        std::int64_t previous_end = 0;
        for(std::size_t index = 0; index < ranges.size(); ++index) {
            const auto [start, finish] = ranges[index];
            if(start == -1 && finish == -1) {
                result.unknown = true;
                continue;
            }
            if(start == 0 && finish == 0) continue;
            EXPECT_GE(start, 0);
            EXPECT_GE(finish, start);
            EXPECT_LE(static_cast<std::size_t>(finish), block.size());
            EXPECT_GE(start, previous_end);
            if(start < 0 || finish < start ||
               static_cast<std::size_t>(finish) > block.size()) continue;
            result.body.append(block.substr(static_cast<std::size_t>(start),
                                            static_cast<std::size_t>(finish - start)));
            result.encodings.push_back(encodings[index]);
            previous_end = finish;
        }
    }
    return result;
}

void expect_every_single_split(std::string_view wire,
                               std::string_view expected_body,
                               bool response_side) {
    for(std::size_t split = 0; split <= wire.size(); ++split) {
        SCOPED_TRACE(::testing::Message() << "split=" << split);
        auto observed = observe_segments(wire, {split}, response_side);
        EXPECT_FALSE(observed.unknown);
        EXPECT_EQ(observed.body, expected_body);
    }
}

void expect_every_double_split(std::string_view wire,
                               std::string_view expected_body,
                               bool response_side) {
    for(std::size_t first = 0; first <= wire.size(); ++first) {
        for(std::size_t second = first; second <= wire.size(); ++second) {
            SCOPED_TRACE(::testing::Message()
                         << "first=" << first << " second=" << second);
            auto observed = observe_segments(wire, {first, second}, response_side);
            EXPECT_FALSE(observed.unknown);
            EXPECT_EQ(observed.body, expected_body);
        }
    }
}

std::vector<std::size_t> random_cuts(std::size_t size, std::mt19937& random) {
    std::vector<std::size_t> cuts;
    std::uniform_int_distribution<std::size_t> count_distribution(0, 24);
    std::uniform_int_distribution<std::size_t> cut_distribution(0, size);
    const auto count = count_distribution(random);
    cuts.reserve(count);
    for(std::size_t i = 0; i < count; ++i) cuts.push_back(cut_distribution(random));
    return cuts;
}

std::vector<std::size_t> every_byte_cut(std::size_t size) {
    std::vector<std::size_t> cuts;
    cuts.reserve(size + 1);
    for(std::size_t offset = 0; offset <= size; ++offset) cuts.push_back(offset);
    return cuts;
}

} // namespace

TEST(Http1Framing, FixedRequestBodySurvivesEverySingleSplit) {
    const std::string body("alpha\0beta\r\ngamma", 17);
    const std::string wire =
        "POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + body;
    expect_every_single_split(wire, body, false);
}

TEST(Http1Framing, FixedResponseBodySurvivesEveryDoubleSplit) {
    const std::string body = "response-body";
    const std::string wire =
        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n" + body;
    expect_every_double_split(wire, body, true);
}

TEST(Http1Framing, ChunkedBodySurvivesEveryDoubleSplit) {
    const std::string wire =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Encoding: gzip\r\n\r\n"
        "5;name=first\r\nhello\r\n"
        "1\r\n \r\n"
        "5\r\nworld\r\n"
        "0\r\nX-Checksum: yes\r\n\r\n";
    expect_every_double_split(wire, "hello world", true);
}

TEST(Http1Framing, FixedAndChunkedMessagesSurviveByteAtATimeDelivery) {
    const std::string fixed =
        "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nabcde";
    auto observed = observe_segments(fixed, every_byte_cut(fixed.size()), false);
    EXPECT_FALSE(observed.unknown);
    EXPECT_EQ(observed.body, "abcde");

    const std::string chunked =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "2;foo=bar\r\nab\r\n3\r\ncde\r\n0\r\nTrailer: x\r\n\r\n";
    observed = observe_segments(chunked, every_byte_cut(chunked.size()), true);
    EXPECT_FALSE(observed.unknown);
    EXPECT_EQ(observed.body, "abcde");
}

TEST(Http1Framing, LfOnlyFramingSurvivesEverySingleSplit) {
    const std::string wire =
        "POST / HTTP/1.1\nHost: test\nContent-Length: 4\n\ndata";
    expect_every_single_split(wire, "data", false);
}

TEST(Http1Framing, PipelinedRequestsKeepOnlyBodies) {
    const std::string wire =
        "POST /one HTTP/1.1\r\nHost: test\r\nContent-Length: 3\r\n\r\none"
        "GET /none HTTP/1.1\r\nHost: test\r\n\r\n"
        "POST /two HTTP/1.1\r\nHost: test\r\nContent-Length: 3\r\n\r\ntwo";
    expect_every_single_split(wire, "onetwo", false);
}

TEST(Http1Framing, InformationalAndBodylessResponsesStayOutOfPayload) {
    const std::string wire =
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 204 No Content\r\nDate: now\r\n\r\n"
        "HTTP/1.1 304 Not Modified\r\nETag: x\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    expect_every_single_split(wire, "ok", true);
}

TEST(Http1Framing, HeadResponseNeverPublishesAnApparentBody) {
    Http1Connection connection;
    connection.observe(0, "HEAD / HTTP/1.1\r\nHost: test\r\n\r\n", false);
    EXPECT_EQ(connection.observe(
                  1, "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n", true),
              L7PayloadHints({{0, 0}}));
}

TEST(Http1Framing, InformationalResponseDoesNotConsumeHeadMethod) {
    Http1Connection connection;
    connection.observe(0, "HEAD / HTTP/1.1\r\nHost: test\r\n\r\n", false);
    const std::string responses =
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n";
    EXPECT_EQ(connection.observe(1, responses, true), L7PayloadHints({{0, 0}}));
}

TEST(Http1Framing, PipelinedRequestMethodsAreMatchedInOrder) {
    Http1Connection connection;
    const std::string requests =
        "HEAD /metadata HTTP/1.1\r\nHost: test\r\n\r\n"
        "GET /body HTTP/1.1\r\nHost: test\r\n\r\n";
    connection.observe(0, requests, false);

    const std::string responses =
        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const auto ranges = connection.observe(1, responses, true);
    ASSERT_EQ(ranges.size(), 1U);
    EXPECT_EQ(responses.substr(static_cast<std::size_t>(ranges[0].first),
                               static_cast<std::size_t>(ranges[0].second - ranges[0].first)),
              "ok");
}

TEST(Http1Framing, SuccessfulConnectSwitchesToOpaqueTunnel) {
    Http1Connection connection;
    connection.observe(0, "CONNECT host:443 HTTP/1.1\r\nHost: host\r\n\r\n", false);
    EXPECT_EQ(connection.observe(
                  1, "HTTP/1.1 200 Connection established\r\n\r\nTLS", true),
              L7PayloadHints({{-1, -1}}));
}

TEST(Http1Framing, InvalidRequestDoesNotPoisonResponseMethodQueue) {
    Http1Connection connection;
    EXPECT_EQ(connection.observe(
                  0, "HEAD /bad HTTP/1.1\r\nContent-Length: nope\r\n\r\n", false),
              L7PayloadHints({{-1, -1}}));

    // A malformed request must not leave HEAD queued and suppress an
    // otherwise ordinary response body.
    const std::string response =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const auto ranges = connection.observe(1, response, true);
    ASSERT_EQ(ranges.size(), 1U);
    EXPECT_EQ(response.substr(static_cast<std::size_t>(ranges[0].first),
                               static_cast<std::size_t>(ranges[0].second - ranges[0].first)),
              "ok");
}

TEST(Http1Framing, CloseDelimitedResponseContinuesAcrossAllBlocks) {
    const std::string wire =
        "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nabcdefghijk";
    expect_every_single_split(wire, "abcdefghijk", true);
}

TEST(Http1Framing, DuplexDirectionsRemainIndependent) {
    Http1Connection connection;
    const std::string request =
        "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\nabc";
    const std::string response =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxyz\r\n0\r\n\r\n";

    auto left = connection.observe(0, request, false);
    ASSERT_EQ(left.size(), 1U);
    EXPECT_EQ(request.substr(static_cast<std::size_t>(left[0].first),
                             static_cast<std::size_t>(left[0].second - left[0].first)),
              "abc");

    auto right = connection.observe(1, response, true);
    ASSERT_EQ(right.size(), 1U);
    EXPECT_EQ(response.substr(static_cast<std::size_t>(right[0].first),
                              static_cast<std::size_t>(right[0].second - right[0].first)),
              "xyz");

    left = connection.observe(0, "def", false);
    EXPECT_EQ(left, L7PayloadHints({{0, 3}}));
}

TEST(Http1Framing, EncodingIsAttachedToEveryBodyRange) {
    Http1Direction direction;
    const std::string wire =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
        "Content-Encoding: br\r\n\r\n1\r\na\r\n1\r\nb\r\n0\r\n\r\n";
    const auto ranges = direction.observe(wire, true);
    ASSERT_EQ(ranges.size(), 2U);
    ASSERT_EQ(direction.encodings().size(), 2U);
    EXPECT_EQ(direction.encodings()[0], "br");
    EXPECT_EQ(direction.encodings()[1], "br");
}

TEST(Http1Framing, InvalidContentLengthFailsClosed) {
    for(const std::string value : {"-1", "+1", "1x", "18446744073709551616"}) {
        SCOPED_TRACE(value);
        Http1Direction direction;
        const auto ranges = direction.observe(
            "HTTP/1.1 200 OK\r\nContent-Length: " + value + "\r\n\r\nx", true);
        EXPECT_EQ(ranges, L7PayloadHints({{-1, -1}}));
    }
}

TEST(Http1Framing, DuplicateAndAmbiguousLengthsFailClosed) {
    const std::vector<std::string> headers {
        "Content-Length: 1\r\nContent-Length: 2\r\n",
        "Content-Length: 1\r\nContent-Length: 1\r\n",
        "Content-Length: 1, 1\r\n"
    };
    for(const auto& framing : headers) {
        SCOPED_TRACE(framing);
        Http1Direction direction;
        const auto ranges = direction.observe(
            "POST / HTTP/1.1\r\nHost: test\r\n" + framing + "\r\nx", false);
        EXPECT_EQ(ranges, L7PayloadHints({{-1, -1}}));
    }
}

TEST(Http1Framing, UnsupportedTransferCodingFailsClosed) {
    for(const std::string value : {"gzip", "chunked, gzip", "gzip, chunked, identity"}) {
        SCOPED_TRACE(value);
        Http1Direction direction;
        const auto ranges = direction.observe(
            "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: " + value +
            "\r\n\r\ndata",
            false);
        EXPECT_EQ(ranges, L7PayloadHints({{-1, -1}}));
    }
}

TEST(Http1Framing, TransferEncodingTakesPrecedenceOverContentLength) {
    const std::string wire =
        "POST / HTTP/1.1\r\nHost: test\r\n"
        "Transfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n"
        "3\r\nabc\r\n0\r\n\r\n";
    expect_every_single_split(wire, "abc", false);
}

TEST(Http1Framing, InvalidChunkSyntaxFailsClosed) {
    const std::vector<std::string> invalid_framings {
        "z\r\ninvalid\r\n",
        "1\r\nx!\r\n",
        std::string(129, 'f') + "\r\n"
    };
    for(const auto& framing : invalid_framings) {
        SCOPED_TRACE(framing.size());
        Http1Direction direction;
        const auto ranges = direction.observe(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + framing,
            true);
        EXPECT_EQ(ranges, L7PayloadHints({{-1, -1}}));
    }
}

TEST(Http1Framing, OversizedIncompleteHeadersFailClosed) {
    Http1Direction direction;
    const auto ranges = direction.observe(std::string(65537, 'x'), false);
    EXPECT_EQ(ranges, L7PayloadHints({{-1, -1}}));
    EXPECT_EQ(direction.observe("anything", false), L7PayloadHints({{-1, -1}}));
}

TEST(Http1Framing, DeterministicRandomSegmentationPreservesPayload) {
    const std::string fixed_body(4096, '\x5a');
    const std::string fixed =
        "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n" + fixed_body;
    const std::string chunked =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "10\r\n0123456789abcdef\r\n"
        "8\r\nABCDEFGH\r\n0\r\nTrailer: value\r\n\r\n";

    std::mt19937 random(0x53585031U);
    for(std::size_t iteration = 0; iteration < 1000; ++iteration) {
        SCOPED_TRACE(iteration);
        auto observed = observe_segments(fixed, random_cuts(fixed.size(), random), true);
        EXPECT_FALSE(observed.unknown);
        EXPECT_EQ(observed.body, fixed_body);

        observed = observe_segments(chunked, random_cuts(chunked.size(), random), true);
        EXPECT_FALSE(observed.unknown);
        EXPECT_EQ(observed.body, "0123456789abcdefABCDEFGH");
    }
}

TEST(Http1Framing, MegabyteBodySurvivesRandomBlockBoundaries) {
    const std::string body(1024U * 1024U, '\xa5');
    const std::string wire =
        "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\n\r\n" + body;
    std::mt19937 random(0x4c37424fU);
    for(std::size_t iteration = 0; iteration < 32; ++iteration) {
        auto observed = observe_segments(wire, random_cuts(wire.size(), random), true);
        ASSERT_FALSE(observed.unknown);
        ASSERT_EQ(observed.body, body);
    }
}

TEST(Http1Framing, RandomGarbageNeverReturnsOutOfBoundsRanges) {
    std::mt19937 random(0x48545450U);
    std::uniform_int_distribution<int> length_distribution(0, 2048);
    std::uniform_int_distribution<int> byte_distribution(0, 255);
    for(std::size_t iteration = 0; iteration < 2000; ++iteration) {
        Http1Direction direction;
        std::string data(static_cast<std::size_t>(length_distribution(random)), '\0');
        for(char& byte : data) byte = static_cast<char>(byte_distribution(random));
        const auto ranges = direction.observe(data, (iteration & 1U) != 0);
        std::int64_t previous_end = 0;
        for(const auto [start, finish] : ranges) {
            if(start == -1 && finish == -1) continue;
            EXPECT_GE(start, 0);
            EXPECT_GE(finish, start);
            EXPECT_LE(static_cast<std::size_t>(finish), data.size());
            EXPECT_GE(start, previous_end);
            previous_end = finish;
        }
    }
}

TEST(Http1Framing, ObservationIdentityRejectsStaleAndModifiedBlocks) {
    sx::engine::http::app_HttpRequest app;
    const std::string with_nul("ab\0cd", 5);
    app.observe_l7_payload(with_nul, 42, {{1, 4}}, {"gzip"});

    EXPECT_TRUE(app.l7_payload_matches(with_nul, 42));
    EXPECT_FALSE(app.l7_payload_matches(std::string("ab\0ce", 5), 42));
    EXPECT_FALSE(app.l7_payload_matches(with_nul, 41));
    EXPECT_FALSE(app.l7_payload_matches(std::string_view(with_nul).substr(0, 4), 42));
}

TEST(ContentWebhookL7Metadata, SerializesUnknownAndNoPayloadExactly) {
    auto unknown = sx::proxy::l7_payload_metadata({{-1, -1}}, {""});
    EXPECT_EQ(unknown["L7_payload_start"], nlohmann::json::array({-1}));
    EXPECT_EQ(unknown["L7_payload_end"], nlohmann::json::array({-1}));
    EXPECT_EQ(unknown["L7_encoding"], nlohmann::json::array({""}));

    auto none = sx::proxy::l7_payload_metadata({{0, 0}}, {""});
    EXPECT_EQ(none["L7_payload_start"], nlohmann::json::array({0}));
    EXPECT_EQ(none["L7_payload_end"], nlohmann::json::array({0}));
    EXPECT_EQ(none["L7_encoding"], nlohmann::json::array({""}));

    EXPECT_EQ(sx::proxy::l7_payload_metadata({}, {}), unknown);
}

TEST(ContentWebhookL7Metadata, SerializesMultipleRangesAndEncodingsExactly) {
    const auto metadata = sx::proxy::l7_payload_metadata(
        {{17, 23}, {31, 47}}, {"gzip", "br"});
    EXPECT_EQ(metadata["L7_payload_start"], nlohmann::json::array({17, 31}));
    EXPECT_EQ(metadata["L7_payload_end"], nlohmann::json::array({23, 47}));
    EXPECT_EQ(metadata["L7_encoding"], nlohmann::json::array({"gzip", "br"}));
    EXPECT_EQ(nlohmann::json::parse(metadata.dump()), metadata);
}

TEST(ContentWebhookL7Metadata, EncodingCardinalityMismatchFailsToEmptyValues) {
    const auto metadata = sx::proxy::l7_payload_metadata(
        {{1, 2}, {3, 4}}, {"gzip"});
    EXPECT_EQ(metadata["L7_encoding"], nlohmann::json::array({"", ""}));
}

TEST(ContentWebhookL7Metadata, UsesIndicesRelativeToEachReceivedBlock) {
    Http1Direction direction;
    const std::string first =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
        "Content-Encoding: gzip\r\n\r\n5\r\nhe";
    auto ranges = direction.observe(first, true);
    auto metadata = sx::proxy::l7_payload_metadata(ranges, direction.encodings());
    EXPECT_EQ(metadata["L7_payload_start"],
              nlohmann::json::array({static_cast<std::int64_t>(first.size() - 2)}));
    EXPECT_EQ(metadata["L7_payload_end"],
              nlohmann::json::array({static_cast<std::int64_t>(first.size())}));
    EXPECT_EQ(metadata["L7_encoding"], nlohmann::json::array({"gzip"}));

    const std::string continuation = "llo\r\n6\r\n wor";
    ranges = direction.observe(continuation, true);
    metadata = sx::proxy::l7_payload_metadata(ranges, direction.encodings());
    EXPECT_EQ(metadata["L7_payload_start"], nlohmann::json::array({0, 8}));
    EXPECT_EQ(metadata["L7_payload_end"], nlohmann::json::array({3, 12}));
    EXPECT_EQ(metadata["L7_encoding"], nlohmann::json::array({"gzip", "gzip"}));
    for(const auto& end : metadata["L7_payload_end"])
        EXPECT_LE(end.get<std::size_t>(), continuation.size());
}

TEST(ContentWebhookAnnotations, Http1MapsFramingAndBodyBytes) {
    Http1Direction direction;
    const std::string wire =
        "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\ndata";
    const auto ranges = direction.observe(wire, false);
    const auto metadata = sx::proxy::l7_payload_metadata(
        ranges, direction.encodings(), direction.annotations());
    const auto body_start = static_cast<std::int64_t>(wire.size() - 4);
    ASSERT_EQ(metadata["content_annotations"].size(), 3U);
    const auto first_line_end = static_cast<std::int64_t>(wire.find('\n') + 1);
    EXPECT_EQ(metadata["content_annotations"][0],
              nlohmann::json::array({0, first_line_end, "http1.start_line"}));
    EXPECT_EQ(metadata["content_annotations"][1],
              nlohmann::json::array({first_line_end, body_start, "http1.headers"}));
    EXPECT_EQ(metadata["content_annotations"][2],
              nlohmann::json::array({body_start,
                                     static_cast<std::int64_t>(wire.size()),
                                     "http1.body"}));
}

TEST(ContentWebhookAnnotations, Http1ChunkedAnnotationsCoverEveryByte) {
    Http1Direction direction;
    const std::string wire =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "2\r\nhi\r\n0\r\n\r\n";
    direction.observe(wire, true);
    std::int64_t cursor = 0;
    for(const auto& annotation : direction.annotations()) {
        EXPECT_EQ(annotation.start, cursor);
        EXPECT_GE(annotation.end, annotation.start);
        cursor = annotation.end;
    }
    EXPECT_EQ(cursor, static_cast<std::int64_t>(wire.size()));
}
