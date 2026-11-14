#include <inspect/engine/http3.hpp>
#include <inspect/engine/http3_settings.hpp>
#include <inspect/engine/http3_adapter.hpp>
#include <inspect/protocol_views.hpp>
#include <gtest/gtest.h>
#include <lsqpack.h>
#include <lsxpack_header.h>
#include <random>

namespace {
using namespace sx::engine;
namespace h3 = sx::engine::http::v3;
using E = ProtocolEndpoint;
using V = ProtocolViews;

std::vector<unsigned char> encode_fields(
    std::vector<std::pair<std::string, std::string>> const& fields) {
    lsqpack_enc encoder {};
    std::array<unsigned char, LSQPACK_LONGEST_SDTC> capacity_instruction {};
    std::size_t capacity_size = capacity_instruction.size();
    if(lsqpack_enc_init(&encoder, nullptr, 0, 0, 0,
                        static_cast<lsqpack_enc_opts>(0),
                        capacity_instruction.data(), &capacity_size) != 0) {
        return {};
    }
    if(lsqpack_enc_start_header(&encoder, 0, 0) != 0) {
        lsqpack_enc_cleanup(&encoder);
        return {};
    }

    std::vector<unsigned char> payload;
    for(auto const& [name, value]: fields) {
        std::string storage = name + value;
        lsxpack_header field {};
        lsxpack_header_set_offset2(&field, storage.data(), 0, name.size(),
                                   name.size(), value.size());
        std::array<unsigned char, 16> encoder_output {};
        std::array<unsigned char, 512> field_output {};
        std::size_t encoder_size = encoder_output.size();
        std::size_t field_size = field_output.size();
        if(lsqpack_enc_encode(
               &encoder, encoder_output.data(), &encoder_size,
               field_output.data(), &field_size, &field,
               static_cast<lsqpack_enc_flags>(LQEF_NO_INDEX | LQEF_NO_DYN))
           != LQES_OK) {
            lsqpack_enc_cleanup(&encoder);
            return {};
        }
        payload.insert(payload.end(), field_output.begin(),
                       field_output.begin() + field_size);
    }

    std::array<unsigned char, 32> prefix {};
    lsqpack_enc_header_flags flags {};
    auto const prefix_size = lsqpack_enc_end_header(
        &encoder, prefix.data(), prefix.size(), &flags);
    lsqpack_enc_cleanup(&encoder);
    if(prefix_size <= 0 || static_cast<std::size_t>(prefix_size) + payload.size() >= 64)
        return {};

    std::vector<unsigned char> frame {
        0x01, static_cast<unsigned char>(prefix_size + payload.size())};
    frame.insert(frame.end(), prefix.begin(), prefix.begin() + prefix_size);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}


buffer bytes(std::vector<unsigned char> const& value) {
    buffer result;
    result.assign(value.data(), value.size());
    return result;
}

V make_views(V::Mode mode = V::Mode::Observe) {
    V views(h3::protocol_adapter(), mode);
    auto& ctx = views.context(E::Client);
    ctx.negotiated_alpn = "h3";
    buffer empty;
    EXPECT_EQ(ProtocolAdapter::Preparation::Ready,
              h3::protocol_adapter().prepare(ctx, true, empty));
    return views;
}

h3::Http3Connection& state(V& views, E endpoint = E::Client) {
    return std::any_cast<h3::Http3Connection&>(views.context(endpoint).state_data);
}

void exchange(V& views, E sender, std::uint64_t id, buffer const& input,
              buffer const& output) {
    const ProtocolStream key{id, 1};
    const auto token = views.begin(ProtocolInput{sender, input, key}, input.size());
    views.finish(token, ProtocolInput{sender, output, key});
}

void pass(V& views, E sender, std::uint64_t id, std::vector<unsigned char> const& value) {
    auto data = bytes(value);
    exchange(views, sender, id, data, data);
}

std::vector<unsigned char> request(std::string method = "GET") {
    return encode_fields({{":method", method}, {":scheme", "https"},
                          {":authority", "example.test"}, {":path", "/"}});
}

TEST(Http3Engine, SharedInspectionAndLazyRewriteHaveIndependentHeaders) {
    auto views = make_views();
    EXPECT_TRUE(views.owns_content_metadata());
    pass(views, E::Client, 0, request());
    EXPECT_FALSE(views.split());
    EXPECT_EQ(&views.context(E::Client), &views.context(E::Server));
    ASSERT_TRUE(views.enable_rewrite());
    EXPECT_TRUE(views.split());

    exchange(views, E::Client, 4, bytes(request("POST")), bytes(request("GET")));
    const ProtocolStream key{4, 1};
    EXPECT_EQ("POST", state(views, E::Client).streams.at(key).application->http_data.method);
    EXPECT_EQ("GET", state(views, E::Server).streams.at(key).application->http_data.method);
    EXPECT_NE(state(views, E::Client).decoder, state(views, E::Server).decoder);
    pass(views, E::Server, 4, encode_fields({{":status", "200"}}));
    for (auto endpoint : {E::Client, E::Server}) {
        EXPECT_EQ(1U, state(views, endpoint).streams.at(key).directions[1].headers.size());
    }
}

TEST(Http3Engine, ForkInPartialHeadersAndDataFraming) {
    auto views = make_views();
    const auto wire = request();
    pass(views, E::Client, 0, {wire.begin(), wire.begin() + 3});
    ASSERT_TRUE(views.enable_rewrite());
    pass(views, E::Client, 0, {wire.begin() + 3, wire.end()});
    // DATA length and content are deliberately split across callbacks.
    pass(views, E::Client, 0, {0});
    pass(views, E::Client, 0, {3, 'a'});
    pass(views, E::Client, 0, {'b', 'c'});
    for (auto endpoint : {E::Client, E::Server}) {
        auto& stream = state(views, endpoint).streams.at({0, 1});
        EXPECT_EQ("GET", stream.application->http_data.method);
        EXPECT_EQ((sx::engine::http::L7PayloadHints{{0, 2}}), stream.application->l7_payload);
    }
    EXPECT_TRUE(state(views).streams.at({0, 1}).application->l7_payload_observed);
    EXPECT_FALSE(state(views, E::Server).streams.at({0, 1}).application->l7_payload_observed);
}

TEST(Http3Engine, DroppedInputAndInjectedOutputAffectOnlyTheirEndpoint) {
    auto views = make_views(V::Mode::Rewrite);
    EXPECT_FALSE(views.split());
    const auto original = bytes(request());
    const ProtocolStream key{0, 1};
    const auto token = views.begin(ProtocolInput{E::Client, original, key}, original.size());
    views.abandon(token);
    EXPECT_TRUE(views.split());
    EXPECT_EQ(1U, state(views).streams.count(key));
    EXPECT_EQ(0U, state(views, E::Server).streams.count(key));

    auto replacement = bytes(request("POST"));
    views.inject(ProtocolInput{E::Client, replacement, key});
    EXPECT_EQ("GET", state(views).streams.at(key).application->http_data.method);
    EXPECT_EQ("POST", state(views, E::Server).streams.at(key).application->http_data.method);
}

TEST(Http3Engine, LifecycleWithoutPayloadAndStaleTokens) {
    auto views = make_views(V::Mode::Rewrite);
    pass(views, E::Client, 0, request());
    buffer empty;
    ProtocolInput fin{E::Client, empty, ProtocolStream{0, 1}, ProtocolEvent::Fin};
    const auto token = views.begin(fin, 0);
    views.finish(token, fin);
    EXPECT_THROW(views.finish(token, fin), std::logic_error);
    for (auto endpoint : {E::Client, E::Server}) {
        EXPECT_TRUE(state(views, endpoint).streams.at({0, 1}).directions[0].finished);
    }
    ProtocolInput reset{E::Server, empty, ProtocolStream{0, 1}, ProtocolEvent::Reset, 0x10c};
    const auto reset_token = views.begin(reset, 0);
    views.finish(reset_token, reset);
    EXPECT_EQ(0x10cU, state(views).streams.at({0, 1}).directions[1].reset_error);
}

TEST(Http3Engine, ReplayLimitDoesNotStopLiveInspectionOrPretendToFork) {
    auto views = make_views();
    // Unknown unidirectional stream payload is ignored by H3 but is still
    // bounded by the exact replay journal's byte budget.
    std::vector<unsigned char> large(h3::Http3Connection::maximum_history_bytes + 1, 0);
    large[0] = 0x21;
    pass(views, E::Client, 2, large);
    EXPECT_FALSE(views.enable_rewrite());
    EXPECT_FALSE(views.fork_error().empty());
    EXPECT_FALSE(views.split());
    pass(views, E::Client, 0, request());
    EXPECT_EQ("GET", state(views).streams.at({0, 1}).application->http_data.method);
}

void dynamic_fixture(std::vector<unsigned char>& request,
                     std::vector<unsigned char>& encoder_stream, bool response = false) {
    lsqpack_enc encoder {};
    std::array<unsigned char, LSQPACK_LONGEST_SDTC> capacity_instruction {};
    std::size_t capacity_size = capacity_instruction.size();
    ASSERT_EQ(0, lsqpack_enc_init(
        &encoder, nullptr, 4096, 4096, 16, LSQPACK_ENC_OPT_IX_AGGR,
        capacity_instruction.data(), &capacity_size));
    ASSERT_EQ(0, lsqpack_enc_start_header(&encoder, 0, 0));

    std::array<unsigned char, 256> encoder_instructions {};
    std::vector<unsigned char> field_block_payload;
    std::size_t encoder_size = 0;
    auto fields = std::vector<std::tuple<std::string, std::string, lsqpack_enc_flags>>{
            {":method", "GET", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {":scheme", "https", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {":authority", "fixture.example", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {":path", "/", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {"x-demo", "dynamic-value", static_cast<lsqpack_enc_flags>(0)}};
    if (response) {
        fields.erase(fields.begin(), fields.begin() + 4);
        fields.insert(fields.begin(), {":status", "200", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)});
    }
    for(auto const& [name, value, flags] : fields) {
        std::string field_storage = name + value;
        lsxpack_header field {};
        lsxpack_header_set_offset2(&field, field_storage.data(), 0, name.size(),
                                   name.size(), value.size());
        std::array<unsigned char, 256> output {};
        std::size_t instruction_size = encoder_instructions.size() - encoder_size;
        std::size_t output_size = output.size();
        ASSERT_EQ(LQES_OK, lsqpack_enc_encode(
            &encoder, encoder_instructions.data() + encoder_size, &instruction_size,
            output.data(), &output_size, &field, flags));
        encoder_size += instruction_size;
        field_block_payload.insert(field_block_payload.end(), output.begin(),
                                   output.begin() + output_size);
    }

    std::array<unsigned char, 32> prefix {};
    lsqpack_enc_header_flags flags {};
    auto const prefix_size = lsqpack_enc_end_header(
        &encoder, prefix.data(), prefix.size(), &flags);
    ASSERT_GT(prefix_size, 0);
    ASSERT_NE(0, flags & LSQECH_REF_NEW_ENTRIES);

    request = {0x01};
    auto const field_section_size = static_cast<std::size_t>(prefix_size)
                                  + field_block_payload.size();
    ASSERT_LT(field_section_size, 64U);
    request.push_back(static_cast<unsigned char>(field_section_size));
    request.insert(request.end(), prefix.begin(), prefix.begin() + prefix_size);
    request.insert(request.end(), field_block_payload.begin(), field_block_payload.end());

    encoder_stream = {0x02};
    encoder_stream.insert(encoder_stream.end(), capacity_instruction.begin(),
                          capacity_instruction.begin() + capacity_size);
    encoder_stream.insert(encoder_stream.end(), encoder_instructions.begin(),
                          encoder_instructions.begin() + encoder_size);
    lsqpack_enc_cleanup(&encoder);
}

TEST(Http3Engine, ForkPreservesBlockedQpackAcrossStreamsAndFin) {
    std::vector<unsigned char> request, encoder_stream;
    dynamic_fixture(request, encoder_stream);
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(encoder_stream.empty());
    auto views = make_views();
    pass(views, E::Server, 3, {0x00, 0x04, 0x05, 0x01, 0x50, 0x00, 0x07, 0x10});
    pass(views, E::Client, 0, request);
    pass(views, E::Client, 4, request);
    pass(views, E::Client, 8, request);
    EXPECT_FALSE(state(views).streams.at({0, 1}).application->populated());

    // Stream 0 finishes before its QPACK dependency arrives. FIN must retain
    // the blocked field section, including across the lazy session fork.
    buffer empty;
    ProtocolInput fin{E::Client, empty, ProtocolStream{0, 1}, ProtocolEvent::Fin};
    const auto token = views.begin(fin, 0);
    views.finish(token, fin);
    ASSERT_TRUE(views.enable_rewrite());
    ProtocolInput reset{E::Client, empty, ProtocolStream{8, 1}, ProtocolEvent::Reset, 0x10c};
    const auto reset_token = views.begin(reset, 0);
    views.finish(reset_token, reset);
    pass(views, E::Client, 2, encoder_stream);
    for (auto endpoint : {E::Client, E::Server}) {
        for (auto id : {0U, 4U}) {
            auto& stream = state(views, endpoint).streams.at({id, 1});
            EXPECT_EQ("GET", stream.application->http_data.method);
            ASSERT_EQ(1U, stream.directions[0].headers.size());
            EXPECT_EQ("dynamic-value", stream.directions[0].headers[0].back().value);
        }
        EXPECT_FALSE(state(views, endpoint).streams.at({2, 1}).application->populated());
        EXPECT_FALSE(state(views, endpoint).streams.at({8, 1}).application->populated());
    }
}

TEST(Http3Engine, BatchedOutputTargetsSeparateStreamsWithoutInputPublication) {
    auto views = make_views(V::Mode::Rewrite);
    auto incoming = bytes(request());
    auto forwarded = bytes(request("POST"));
    auto other = bytes(request());
    const auto token = views.begin(ProtocolInput{E::Client, incoming, ProtocolStream{0, 1}}, 1);
    views.finish(token, std::vector<ProtocolInput>{
        {E::Client, forwarded, ProtocolStream{0, 1}},
        {E::Client, other, ProtocolStream{4, 1}}});
    EXPECT_EQ(0U, state(views).streams.count({4, 1}));
    EXPECT_EQ("POST", state(views, E::Server).streams.at({0, 1}).application->http_data.method);
    EXPECT_EQ("GET", state(views, E::Server).streams.at({4, 1}).application->http_data.method);
}

TEST(Http3Engine, UnexpectedRawRewriteIsAcceptedAndDiagnosed) {
    auto views = make_views();
    exchange(views, E::Client, 0, bytes(request()), bytes(request("POST")));
    EXPECT_FALSE(views.split());
    EXPECT_FALSE(views.fork_error().empty());
    EXPECT_FALSE(views.enable_rewrite());
    pass(views, E::Client, 4, request());
    EXPECT_EQ("GET", state(views).streams.at({4, 1}).application->http_data.method);
}

TEST(Http3Engine, EveryHeaderBoundaryCanBeForked) {
    const auto wire = request();
    for (std::size_t boundary = 1; boundary < wire.size(); ++boundary) {
        auto views = make_views();
        pass(views, E::Client, 0, {wire.begin(), wire.begin() + boundary});
        ASSERT_TRUE(views.enable_rewrite()) << boundary;
        pass(views, E::Client, 0, {wire.begin() + boundary, wire.end()});
        for (auto endpoint : {E::Client, E::Server}) {
            EXPECT_EQ("GET", state(views, endpoint).streams.at({0, 1}).application->http_data.method)
                << boundary;
        }
    }
}

TEST(Http3Engine, ResponseRewriteKeepsEndpointContentEncodingIndependent) {
    auto views = make_views(V::Mode::Rewrite);
    pass(views, E::Client, 0, request());
    auto original = bytes(encode_fields({{":status", "200"}, {"content-encoding", "gzip"}}));
    auto changed = bytes(encode_fields({{":status", "200"}, {"content-encoding", "br"}}));
    exchange(views, E::Server, 0, original, changed);
    pass(views, E::Server, 0, {0, 3, 'a', 'b', 'c'});
    EXPECT_EQ(std::vector<std::string>{"gzip"},
              state(views, E::Server).streams.at({0, 1}).application->l7_encoding);
    EXPECT_EQ(std::vector<std::string>{"br"},
              state(views, E::Client).streams.at({0, 1}).application->l7_encoding);
    // Looking at another stream must not replace the first stream's metadata.
    views.stream_context(E::Server, {4, 1});
    auto& selected = views.stream_context(E::Server, {0, 1});
    EXPECT_EQ(state(views, E::Server).streams.at({0, 1}).application, selected.application_data);
}

TEST(Http3Engine, InPlaceRawRewriteDoesNotOverwriteTheOriginalObservation) {
    auto views = make_views();
    auto data = bytes(request());
    const auto token = views.begin(ProtocolInput{E::Client, data, ProtocolStream{0, 1}}, 1);
    const auto replacement = request("POST");
    data.assign(replacement.data(), replacement.size());
    views.finish(token, data);
    EXPECT_FALSE(views.fork_error().empty());
    EXPECT_EQ("GET", state(views).streams.at({0, 1}).application->http_data.method);
}

} // namespace

TEST(Http3Engine, AnnotationsCoverEveryFragmentWithoutInventingPayload) {
    auto wire = request();
    const auto header_end = wire.size();
    wire.insert(wire.end(), {0x00, 0x03, 'a', 'b', 'c'});
    for (std::size_t split = 1; split < wire.size(); ++split) {
        SCOPED_TRACE(split);
        auto views = make_views();
        for (auto const& bounds : {std::pair{std::size_t{0}, split},
                                   std::pair{split, wire.size()}}) {
            pass(views, E::Client, 0, {wire.begin() + bounds.first, wire.begin() + bounds.second});
            auto const& app = *state(views).streams.at({0, 1}).application;
            std::size_t cursor = 0;
            for (auto const& annotation : app.payload_annotations) {
                EXPECT_EQ(cursor, annotation.start);
                EXPECT_GT(annotation.end, annotation.start);
                EXPECT_LE(annotation.end, bounds.second - bounds.first);
                EXPECT_EQ(0, std::get<std::int64_t>(annotation.attributes.at("stream_id")));
                if (annotation.kind == "h3.data") {
                    EXPECT_GE(bounds.first + annotation.start, header_end + 2);
                    EXPECT_EQ("DATA", std::get<std::string>(annotation.attributes.at("frame_type")));
                }
                cursor = annotation.end;
            }
            EXPECT_EQ(bounds.second - bounds.first, cursor);
            for (auto const& range : app.l7_payload) {
                if (range.first == range.second) continue;
                EXPECT_GE(bounds.first + range.first, header_end + 2);
                EXPECT_LE(bounds.first + range.second, wire.size());
            }
        }
    }
}

TEST(Http3Engine, AnnotationsDistinguishControlAndQpackStreams) {
    auto views = make_views();
    pass(views, E::Client, 2, {0x00, 0x04, 0x00}); // Control type + empty SETTINGS.
    auto const& control = *state(views).streams.at({2, 1}).application;
    ASSERT_EQ(2U, control.payload_annotations.size());
    EXPECT_EQ("h3.stream.type", control.payload_annotations[0].kind);
    EXPECT_EQ("h3.frame.header", control.payload_annotations[1].kind);
    EXPECT_EQ("SETTINGS", std::get<std::string>(control.payload_annotations[1].attributes.at("frame_type")));
    EXPECT_EQ((sx::engine::http::L7PayloadHints{{0, 0}}), control.l7_payload);

    pass(views, E::Client, 6, {0x40}); // Split two-byte stream type.
    auto& encoder = *state(views).streams.at({6, 1}).application;
    ASSERT_EQ(1U, encoder.payload_annotations.size());
    EXPECT_EQ("h3.stream.type", encoder.payload_annotations.front().kind);
    EXPECT_EQ(0U, encoder.payload_annotations.front().attributes.count("stream_type"));
    pass(views, E::Client, 6, {0x02, 0x20}); // QPACK encoder + capacity zero.
    ASSERT_EQ(2U, encoder.payload_annotations.size());
    EXPECT_EQ("h3.qpack.encoder", encoder.payload_annotations.back().kind);
    EXPECT_EQ(1, encoder.payload_annotations.back().start);
    EXPECT_EQ(2, std::get<std::int64_t>(encoder.payload_annotations.back().attributes.at("stream_type")));
    EXPECT_EQ((sx::engine::http::L7PayloadHints{{0, 0}}), encoder.l7_payload);

    pass(views, E::Server, 3, {0x01, 0x00, 0x00, 0x01, 'x'}); // Opaque push stream.
    auto const& push = *state(views).streams.at({3, 1}).application;
    EXPECT_EQ("h3.stream.payload", push.payload_annotations.back().kind);
    EXPECT_EQ((sx::engine::http::L7PayloadHints{{-1, -1}}), push.l7_payload);

    pass(views, E::Client, 10, {0x03, 0x00});
    EXPECT_EQ("h3.qpack.decoder", state(views).streams.at({10, 1}).application->payload_annotations.back().kind);
}

TEST(Http3Engine, SplitKeepsAnnotationOffsetsLocalToEachEndpoint) {
    auto views = make_views(V::Mode::Rewrite);
    pass(views, E::Client, 0, request());
    exchange(views, E::Client, 0, bytes({0, 1, 'a'}), bytes({0, 3, 'x', 'y', 'z'}));
    auto const& client = *state(views, E::Client).streams.at({0, 1}).application;
    auto const& server = *state(views, E::Server).streams.at({0, 1}).application;
    EXPECT_EQ(3, client.payload_annotations.back().end);
    EXPECT_EQ(5, server.payload_annotations.back().end);
    EXPECT_TRUE(client.l7_payload_observed);
    EXPECT_FALSE(server.l7_payload_observed); // Output is never a new input webhook.
}

TEST(Http3Engine, EveryEncoderInstructionBoundarySurvivesLateFork) {
    std::vector<unsigned char> header, instructions;
    dynamic_fixture(header, instructions);
    ASSERT_FALSE(instructions.empty());
    for (std::size_t split = 0; split <= instructions.size(); ++split) {
        SCOPED_TRACE(split);
        auto views = make_views();
        pass(views, E::Server, 3, {0, 4, 5, 1, 0x50, 0, 7, 16});
        pass(views, E::Client, 0, header);
        pass(views, E::Client, 2, {instructions.begin(), instructions.begin() + split});
        ASSERT_TRUE(views.enable_rewrite());
        pass(views, E::Client, 2, {instructions.begin() + split, instructions.end()});
        for (auto endpoint : {E::Client, E::Server}) {
            auto const& stream = state(views, endpoint).streams.at({0, 1});
            ASSERT_EQ(1U, stream.directions[0].headers.size());
            EXPECT_EQ("dynamic-value", stream.directions[0].headers[0].back().value);
            EXPECT_EQ("GET", stream.application->http_data.method);
            EXPECT_FALSE(state(views, endpoint).streams.at({2, 1}).application->populated());
        }
    }
}

// Independent wire fixture: two DATA frames separated by an unknown extension.
// The first DATA length uses a two-byte varint, including a splitable prefix.
std::vector<unsigned char> framing_fixture() {
    std::vector<unsigned char> wire {0, 0x40, 70};
    wire.insert(wire.end(), 70, 'a');
    wire.insert(wire.end(), {0x21, 3, 'n', 'o', 't', 0, 2, 'b', 'c'});
    return wire;
}

void check_framing_chunks(std::vector<std::size_t> const& cuts, bool rewrite) {
    auto views = make_views(rewrite ? V::Mode::Rewrite : V::Mode::Observe);
    pass(views, E::Client, 0, request());
    auto wire = framing_fixture();
    std::string recovered;
    std::size_t offset = 0;
    for (auto end : cuts) {
        ASSERT_GE(end, offset);
        ASSERT_LE(end, wire.size());
        if (end == offset) continue;
        pass(views, E::Client, 0, {wire.begin() + offset, wire.begin() + end});
        auto const& app = *state(views).streams.at({0, 1}).application;
        std::int64_t covered = 0;
        for (auto const& annotation : app.payload_annotations) {
            EXPECT_EQ(covered, annotation.start);
            covered = annotation.end;
        }
        EXPECT_EQ(end - offset, covered);
        for (auto [begin, finish] : app.l7_payload) {
            ASSERT_GE(begin, 0);
            ASSERT_GE(finish, begin);
            ASSERT_LE(finish, end - offset);
            recovered.append(wire.begin() + offset + begin, wire.begin() + offset + finish);
        }
        if (rewrite) {
            auto const& peer = *state(views, E::Server).streams.at({0, 1}).application;
            EXPECT_EQ(app.l7_payload, peer.l7_payload);
            EXPECT_EQ(app.payload_annotations, peer.payload_annotations);
            EXPECT_FALSE(peer.l7_payload_observed);
        }
        offset = end;
    }
    EXPECT_EQ(wire.size(), offset);
    EXPECT_EQ(std::string(70, 'a') + "bc", recovered);
}

TEST(Http3Engine, EveryDoubleSplitPreservesOnlyDataPayload) {
    const auto size = framing_fixture().size();
    for (std::size_t first = 1; first < size; ++first) {
        for (std::size_t second = first + 1; second < size; ++second) {
            SCOPED_TRACE(::testing::Message() << first << ',' << second);
            check_framing_chunks({first, second, size}, false);
        }
    }
}

TEST(Http3Engine, DeterministicRandomChunksPreserveBothViews) {
    for (unsigned seed = 0; seed < 128; ++seed) {
        SCOPED_TRACE(seed);
        std::mt19937 random(seed);
        std::vector<std::size_t> cuts;
        std::size_t cursor = 0;
        const auto size = framing_fixture().size();
        while (cursor < size) {
            cursor = std::min(size, cursor + 1 + random() % 13);
            cuts.push_back(cursor);
        }
        check_framing_chunks(cuts, true);
    }
}

TEST(Http3Engine, EventBudgetExhaustionDoesNotBreakOtherStreams) {
    auto views = make_views();
    pass(views, E::Client, 2, {0x21});
    for (std::size_t i = 1; i < h3::Http3Connection::maximum_history_events; ++i) {
        pass(views, E::Client, 2, {0});
    }
    EXPECT_TRUE(state(views).replayable);
    pass(views, E::Client, 2, {0});
    EXPECT_FALSE(state(views).replayable);
    EXPECT_TRUE(state(views).history.empty());
    EXPECT_EQ(0U, state(views).history_bytes);
    EXPECT_FALSE(views.enable_rewrite());
    pass(views, E::Client, 0, request());
    EXPECT_EQ("GET", state(views).streams.at({0, 1}).application->http_data.method);
}

TEST(Http3Engine, ConnectionCloseStopsObservationInBothViews) {
    auto views = make_views(V::Mode::Rewrite);
    pass(views, E::Client, 0, request());
    buffer empty;
    ProtocolInput close{E::Server, empty, std::nullopt, ProtocolEvent::ConnectionClose, 0x100};
    auto token = views.begin(close, 0);
    views.finish(token, close);
    pass(views, E::Client, 4, request("POST"));
    for (auto endpoint : {E::Client, E::Server}) {
        EXPECT_TRUE(state(views, endpoint).closed);
        EXPECT_EQ(0U, state(views, endpoint).streams.count({4, 1}));
        EXPECT_TRUE(state(views, endpoint).history.empty());
    }
}

TEST(Http3Engine, HeaderSectionsPreserveDuplicatesAndTrailers) {
    auto views = make_views(V::Mode::Rewrite);
    pass(views, E::Client, 0, request());
    pass(views, E::Server, 0, encode_fields({{":status", "103"}, {"link", "a"}}));
    pass(views, E::Server, 0, encode_fields({{":status", "200"}, {"set-cookie", "a=1"}, {"set-cookie", "b=2"}}));
    pass(views, E::Server, 0, {0, 1, 'x'});
    pass(views, E::Server, 0, encode_fields({{"x-trailer", "done"}}));
    for (auto endpoint : {E::Client, E::Server}) {
        auto const& sections = state(views, endpoint).streams.at({0, 1}).directions[1].headers;
        ASSERT_EQ(3U, sections.size());
        EXPECT_EQ("103", sections[0][0].value);
        ASSERT_EQ(3U, sections[1].size());
        EXPECT_EQ("set-cookie", sections[1][1].name);
        EXPECT_EQ("a=1", sections[1][1].value);
        EXPECT_EQ("b=2", sections[1][2].value);
        EXPECT_EQ("done", sections[2][0].value);
    }
}

TEST(Http3Engine, FinalEncodingDoesNotInheritInterimOrTrailerFields) {
    auto views = make_views(V::Mode::Rewrite);
    pass(views, E::Client, 0, request());
    pass(views, E::Server, 0, encode_fields({{":status", "103"}, {"content-encoding", "gzip"}}));
    pass(views, E::Server, 0, encode_fields({{":status", "200"}}));
    pass(views, E::Server, 0, {0, 1, 'x'});
    for (auto endpoint : {E::Client, E::Server}) {
        auto const& stream = state(views, endpoint).streams.at({0, 1});
        EXPECT_EQ(std::vector<std::string>{""}, stream.application->l7_encoding);
        EXPECT_TRUE(h3::metadata(views.context(endpoint), 0, E::Server)
                        ["flow.http3.decode"]["encoding_known"].get<bool>());
    }
    pass(views, E::Server, 0, encode_fields({{"content-encoding", "br"}}));
    EXPECT_TRUE(state(views).streams.at({0, 1}).directions[1].encoding.empty());
}

TEST(Http3Engine, MetadataPublishesUnblockedHeadersWithoutAnotherRequestByte) {
    std::vector<unsigned char> header, encoder;
    dynamic_fixture(header, encoder);
    auto views = make_views();
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto id, auto info) {
        info["stream_id"] = id;
        events.push_back(std::move(info));
    };
    pass(views, E::Server, 3, {0, 4, 5, 1, 0x50, 0, 7, 0x10});
    pass(views, E::Client, 0, header);
    EXPECT_EQ("blocked", h3::metadata(views.context(E::Client), 0, E::Client)
                             ["flow.http3.decode"]["state"]);
    buffer empty;
    ProtocolInput fin{E::Client, empty, ProtocolStream{0, 1}, ProtocolEvent::Fin};
    auto token = views.begin(fin, 0);
    views.finish(token, fin);
    ASSERT_TRUE(views.enable_rewrite());
    events.clear();
    pass(views, E::Client, 2, encoder);
    std::size_t headers = 0;
    for (auto const& info : events) {
        if (info["protocol_event"] != "headers") continue;
        ++headers;
        EXPECT_EQ(0, info["stream_id"]);
        EXPECT_EQ("client", info["protocol_endpoint"]);
        EXPECT_EQ("L", info["side"]);
        EXPECT_EQ("GET", info["flow.http3.method"]);
        EXPECT_EQ("request", info["flow.http3.header_section"]);
        EXPECT_FALSE(info.contains("content"));
    }
    EXPECT_EQ(1U, headers); // Fork replay and output do not publish a second event.
}

TEST(Http3Engine, MetadataPreservesResponseSectionsDuplicatesAndTerminalErrors) {
    auto views = make_views(V::Mode::Rewrite);
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto, auto info) { events.push_back(std::move(info)); };
    pass(views, E::Client, 0, request());
    events.clear();
    pass(views, E::Server, 0, encode_fields({{":status", "103"}, {"link", "a"}}));
    pass(views, E::Server, 0, encode_fields({{":status", "200"}, {"set-cookie", "a=1"}, {"set-cookie", "b=2"}}));
    pass(views, E::Server, 0, encode_fields({{"x-trailer", "done"}}));
    std::vector<nlohmann::json> headers;
    for (auto const& info : events)
        if (info["protocol_event"] == "headers") headers.push_back(info);
    ASSERT_EQ(3U, headers.size());
    EXPECT_EQ("interim", headers[0]["flow.http3.header_section"]);
    EXPECT_EQ("200", headers[1]["flow.http3.status"]);
    EXPECT_EQ(nlohmann::json::array({"set-cookie", "a=1"}), headers[1]["flow.http3.headers"][1]);
    EXPECT_EQ(nlohmann::json::array({"set-cookie", "b=2"}), headers[1]["flow.http3.headers"][2]);
    EXPECT_EQ("trailers", headers[2]["flow.http3.header_section"]);
    buffer empty;
    ProtocolInput reset{E::Server, empty, ProtocolStream{0, 1}, ProtocolEvent::Reset, 0x10c};
    auto token = views.begin(reset, 0);
    views.finish(token, reset);
    EXPECT_EQ("reset", events.back()["protocol_event"]);
    EXPECT_EQ(0x10c, events.back()["protocol_error"]);
    EXPECT_EQ("server", events.back()["protocol_endpoint"]);
}

TEST(Http3Engine, ResourceLimitsAndInvalidInputAreExplicitMetadata) {
    auto views = make_views();
    state(views).header_bytes = h3::Http3Connection::maximum_header_bytes;
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto, auto info) { events.push_back(std::move(info)); };
    pass(views, E::Client, 0, request());
    EXPECT_EQ("header-bytes-limit", h3::metadata(views.context(E::Client), 0, E::Client)
                                      ["flow.http3.decode"]["reason"]);
    ASSERT_FALSE(events.empty());
    EXPECT_EQ("headers", events.front()["protocol_event"]);
    EXPECT_FALSE(events.front()["flow.http3.headers"].empty()); // Not silently discarded.

    for (std::uint64_t id = 4; state(views).streams.size() < h3::Http3Connection::maximum_streams; id += 4)
        views.stream_context(E::Client, {id, 1});
    pass(views, E::Client, 20000, request());
    EXPECT_EQ("stream-limit", events.back()["flow.http3.decode"]["reason"]);

    auto invalid = make_views();
    pass(invalid, E::Client, 0, {0, 1, 'x'}); // DATA before request HEADERS.
    EXPECT_EQ("invalid", h3::metadata(invalid.context(E::Client), 0, E::Client)
                             ["flow.http3.decode"]["state"]);
}

TEST(Http3Engine, CriticalEncoderStillUnblocksHeadersAtStreamStorageLimit) {
    std::vector<unsigned char> header, encoder;
    dynamic_fixture(header, encoder);
    auto views = make_views();
    pass(views, E::Server, 3, {0, 4, 5, 1, 0x50, 0, 7, 0x10});
    pass(views, E::Client, 0, header);
    for (std::uint64_t id = 4; state(views).streams.size() < h3::Http3Connection::maximum_streams; id += 4)
        views.stream_context(E::Client, {id, 1});
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto id, auto info) {
        info["stream_id"] = id;
        events.push_back(std::move(info));
    };
    pass(views, E::Client, 2, encoder);
    EXPECT_EQ("GET", state(views).streams.at({0, 1}).application->http_data.method);
    EXPECT_TRUE(std::any_of(events.begin(), events.end(), [](auto const& info) {
        return info["stream_id"] == 0 && info["protocol_event"] == "headers";
    }));
    EXPECT_EQ("stream-limit", events.back()["flow.http3.decode"]["reason"]);
}

TEST(Http3Engine, DecoderBoundsAndResetAfterFinRemainObservable) {
    auto views = make_views();
    pass(views, E::Client, 0, {1, 0x80, 0x10, 0, 1}); // HEADERS length > 1 MiB.
    EXPECT_EQ("limited", h3::metadata(views.context(E::Client), 0, E::Client)
                             ["flow.http3.decode"]["state"]);
    EXPECT_EQ("decoder-limit", h3::metadata(views.context(E::Client), 0, E::Client)
                                   ["flow.http3.decode"]["reason"]);
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto, auto info) { events.push_back(std::move(info)); };
    buffer empty;
    for (auto event : {ProtocolEvent::Fin, ProtocolEvent::Reset}) {
        ProtocolInput input{E::Client, empty, ProtocolStream{0, 1}, event, 0};
        auto token = views.begin(input, 0);
        views.finish(token, input);
    }
    ASSERT_EQ(2U, events.size());
    EXPECT_EQ("fin", events[0]["protocol_event"]);
    EXPECT_EQ("reset", events[1]["protocol_event"]);
    EXPECT_EQ(0, events[1]["protocol_error"]);
}

TEST(Http3Engine, MetadataPreservesNonUtf8BytesAndValidUnicode) {
    auto views = make_views();
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto, auto info) {
        EXPECT_NO_THROW(info.dump());
        events.push_back(std::move(info));
    };
    pass(views, E::Client, 0, request());
    events.clear();
    pass(views, E::Server, 0, encode_fields({{":status", "200"},
        {"x-raw", std::string(1, char(0xff))}, {"x-text", "ž"}}));
    ASSERT_FALSE(events.empty());
    auto const& fields = events.front()["flow.http3.headers"];
    EXPECT_EQ(fields[1][1], nlohmann::json({{"encoding", "base64"}, {"data", "/w=="}}));
    EXPECT_EQ(fields[2][1], "ž");
    // The same conversion protects content metadata, including encoding arrays.
    nlohmann::json content = {{"L7_encoding", {std::string(1, char(0xff))}}};
    h3::encode_metadata_bytes(content);
    EXPECT_NO_THROW(content.dump());
    EXPECT_EQ(content["L7_encoding"][0]["data"], "/w==");
}

TEST(Http3Engine, ConnectionFailureNotifiesIdleStreamsOnce) {
    auto views = make_views();
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto id, auto info) {
        info["stream_id"] = id;
        events.push_back(std::move(info));
    };
    pass(views, E::Client, 0, request());
    pass(views, E::Client, 4, request());
    events.clear();
    pass(views, E::Client, 8, {0, 1, 'x'}); // DATA before HEADERS invalidates the connection.
    for (auto id : {0, 4}) {
        EXPECT_EQ(1, std::count_if(events.begin(), events.end(), [&](auto const& info) {
            return info["stream_id"] == id && info["protocol_event"] == "decode-status"
                && info["flow.http3.decode"]["state"] == "invalid"
                && info["flow.http3.decode"]["encoding_known"] == false;
        }));
    }
    events.clear();
    pass(views, E::Client, 8, {0, 1, 'y'});
    EXPECT_TRUE(events.empty());
}

TEST(Http3Engine, DiagnosticsKeepEndpointViewsAndReplayAvailabilitySeparate) {
    auto views = make_views();
    pass(views, E::Client, 0, request());
    auto shared = h3::diagnostics(views, 0);
    EXPECT_FALSE(shared["split"]);
    EXPECT_EQ(shared["shared"]["request"]["flow.http3.method"], "GET");
    ASSERT_TRUE(views.enable_rewrite());
    exchange(views, E::Client, 4, bytes(request()), bytes(request("POST")));
    auto split = h3::diagnostics(views, 4);
    EXPECT_TRUE(split["split"]);
    EXPECT_EQ(split["client"]["request"]["flow.http3.method"], "GET");
    EXPECT_EQ(split["server"]["request"]["flow.http3.method"], "POST");
    state(views).replayable = false;
    split = h3::diagnostics(views, 4);
    EXPECT_FALSE(split["client"]["replayable"]);
    EXPECT_TRUE(split["server"]["replayable"]);
    EXPECT_NO_THROW(split.dump());
}

TEST(Http3Engine, ConnectionLimitNotifiesIdleStreams) {
    auto views = make_views(V::Mode::Rewrite);
    std::vector<nlohmann::json> events;
    state(views).on_metadata = [&](auto id, auto info) {
        info["stream_id"] = id;
        events.push_back(std::move(info));
    };
    pass(views, E::Client, 0, request());
    pass(views, E::Client, 4, request());
    // Advertise a QPACK table capacity exceeding the observer's 1 MiB bound.
    pass(views, E::Server, 3, {0, 4, 5, 1, 0x80, 0x20, 0, 0});
    events.clear();
    pass(views, E::Client, 8, request());
    for (auto id : {0, 4}) {
        EXPECT_EQ(1, std::count_if(events.begin(), events.end(), [&](auto const& info) {
            return info["stream_id"] == id && info["protocol_event"] == "decode-status"
                && info["flow.http3.decode"]["state"] == "limited"
                && info["flow.http3.decode"]["reason"] == "decoder-limit";
        }));
    }
}

TEST(Http3Engine, BlockedResponseDefersDataAndTrailersUntilQpackRelease) {
    std::vector<unsigned char> header, encoder;
    dynamic_fixture(header, encoder, true);
    for (bool coalesced : {false, true}) {
        auto views = make_views();
        pass(views, E::Client, 2, {0, 4, 5, 1, 0x50, 0, 7, 0x10});
        pass(views, E::Client, 0, request());
        auto following = std::vector<unsigned char>{0, 3, 'a', 'b', 'c'};
        auto trailers = encode_fields({{"x-trailer", "done"}});
        following.insert(following.end(), trailers.begin(), trailers.end());
        if (coalesced) header.insert(header.end(), following.begin(), following.end());
        pass(views, E::Server, 0, header);
        if (!coalesced) pass(views, E::Server, 0, following);
        EXPECT_EQ("blocked", h3::metadata(views.context(E::Server), 0, E::Server)
                                    ["flow.http3.decode"]["state"]);
        buffer empty;
        ProtocolInput fin{E::Server, empty, ProtocolStream{0, 1}, ProtocolEvent::Fin};
        auto token = views.begin(fin, 0);
        views.finish(token, fin);
        ASSERT_TRUE(views.enable_rewrite());
        pass(views, E::Server, 3, encoder);
        for (auto endpoint : {E::Client, E::Server}) {
            EXPECT_EQ("decoded", h3::metadata(views.context(endpoint), 0, E::Server)
                                        ["flow.http3.decode"]["state"]);
            auto const& sections = state(views, endpoint).streams.at({0, 1}).directions[1].headers;
            ASSERT_EQ(2U, sections.size());
            EXPECT_EQ("done", sections.back().front().value);
        }
    }
}

TEST(Http3Engine, BlockedResponseBufferLimitIsExplicitAndDoesNotRegainMetadata) {
    std::vector<unsigned char> header, encoder;
    dynamic_fixture(header, encoder, true);
    auto views = make_views();
    pass(views, E::Client, 2, {0, 4, 5, 1, 0x50, 0, 7, 0x10});
    pass(views, E::Client, 0, request());
    pass(views, E::Server, 0, header);
    pass(views, E::Server, 0, std::vector<unsigned char>(64 * 1024 + 1, 'x'));
    EXPECT_EQ("limited", h3::metadata(views.context(E::Server), 0, E::Server)
                                ["flow.http3.decode"]["state"]);
    pass(views, E::Server, 3, encoder);
    EXPECT_EQ("limited", h3::metadata(views.context(E::Server), 0, E::Server)
                                ["flow.http3.decode"]["state"]);
    EXPECT_TRUE(state(views).streams.at({0, 1}).directions[1].headers.empty());
}

namespace {
TEST(Http3Engine, FirefoxSettingsNormalizationPreservesFramesAtEverySplit) {
    // Captured Firefox control stream rejected by Fastly with H3_FRAME_ERROR:
    // both DATAGRAM settings advertised true on our non-DATAGRAM QUIC leg.
    const std::vector<unsigned char> original {
        0x00, 0x04, 0x15, 0x01, 0x80, 0x01, 0x00, 0x00, 0x07, 0x14,
        0xab, 0x60, 0x37, 0x42, 0x00, 0x80, 0xff, 0xd2, 0x77, 0x01,
        0x33, 0x01, 0x08, 0x01, 0xd8, 0x50, 0xb2, 0xb6, 0xf1, 0x5c,
        0xd3, 0x97, 0x01, 0x26};
    auto expected = original;
    expected[19] = 0;
    expected[21] = 0;

    for (std::size_t split = 0; split <= original.size(); ++split) {
        SCOPED_TRACE(split);
        h3::SettingsNormalizer normalizer;
        buffer result;

        for (auto const& bounds : {std::pair{std::size_t{0}, split},
                                   std::pair{split, original.size()}}) {
            auto chunk = bytes({original.begin() + bounds.first, original.begin() + bounds.second});
            normalizer.apply(chunk);
            result.append(chunk.data(), chunk.size());
        }
        EXPECT_EQ(result.string_view(), bytes(expected).string_view());
    }
}

TEST(Http3Engine, SettingsNormalizationPreservesAllVarintWidthsByteByByte) {
    for (unsigned width : {1U, 2U, 4U, 8U}) {
        SCOPED_TRACE(width);
        std::vector<unsigned char> original {0, 4, static_cast<unsigned char>(1 + width), 0x33};
        const unsigned char tag = width == 1 ? 0 : width == 2 ? 0x40 : width == 4 ? 0x80 : 0xc0;
        original.resize(4 + width, 0);
        original[4] = tag;
        original.back() |= 1;
        auto expected = original;
        expected.back() &= 0xfe;
        h3::SettingsNormalizer normalizer;
        buffer result;

        for (auto byte : original) {
            auto chunk = bytes({byte});
            normalizer.apply(chunk);
            result.append(chunk.data(), chunk.size());
        }
        EXPECT_EQ(result.string_view(), bytes(expected).string_view());
    }
}

TEST(Http3Engine, SettingsNormalizationSkipsOtherStreamsFramesAndSettings) {
    for (auto const& original : std::vector<std::vector<unsigned char>> {
            {2, 0, 4, 2, 0x33, 1}, // QPACK encoder, not control.
            {3, 0, 4, 2, 0x33, 1}, // QPACK decoder.
            {0x21, 0, 4, 2, 0x33, 1}, // Unknown unidirectional stream.
            {0, 4, 0, 7, 2, 0x33, 1}, // Empty SETTINGS and opaque GOAWAY payload.
            {0, 4, 6, 1, 1, 7, 1, 8, 1}}) {
        h3::SettingsNormalizer normalizer;
        auto output = bytes(original);
        normalizer.apply(output);
        EXPECT_EQ(output.string_view(), bytes(original).string_view());
    }
}

TEST(Http3Engine, SettingsNormalizationRejectsMalformedPairsAndBooleanValues) {
    for (auto const& original : std::vector<std::vector<unsigned char>> {
            {0, 4, 1, 0x33}, {0, 4, 2, 0x33, 0x40}, {0, 4, 2, 0x33, 2}}) {
        h3::SettingsNormalizer normalizer;
        auto output = bytes(original);
        EXPECT_THROW(normalizer.apply(output), std::runtime_error);
    }
}

TEST(Http3Engine, NormalizedSettingsRemainSeparateInEndpointHistory) {
    auto views = make_views();
    ASSERT_TRUE(views.enable_rewrite());
    std::array<h3::SettingsNormalizer, 2> normalizers;

    for (auto sender : {E::Client, E::Server}) {
        auto input = bytes({0, 4, 2, 0x33, 1});
        auto output = bytes({0, 4, 2, 0x33, 1});
        const ProtocolStream stream{sender == E::Client ? 2U : 3U, 1};
        auto token = views.begin(ProtocolInput{sender, input, stream}, input.size());
        normalizers[sender == E::Client ? 0 : 1].apply(output);
        views.finish(token, output);

        const auto recipient = sender == E::Client ? E::Server : E::Client;
        ASSERT_FALSE(state(views, sender).history.empty());
        ASSERT_FALSE(state(views, recipient).history.empty());
        EXPECT_EQ(state(views, sender).history.back().bytes.back(), 1);
        EXPECT_EQ(state(views, recipient).history.back().bytes.back(), 0);
    }
    EXPECT_TRUE(views.split());
    EXPECT_TRUE(views.fork_error().empty());
}
} // namespace
