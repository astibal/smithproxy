#include <gtest/gtest.h>

#include "proxy/quic/h3capture.hpp"

#include <lsqpack.h>
#include <lsxpack_header.h>

#include <algorithm>
#include <array>
#include <string>
#include <tuple>
#include <vector>

namespace {

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

std::vector<unsigned char> encode_varint(std::uint64_t value) {
    if(value < 64) return {static_cast<unsigned char>(value)};
    if(value < 16384) {
        return {static_cast<unsigned char>(0x40U | (value >> 8)),
                static_cast<unsigned char>(value)};
    }
    return {};
}

std::vector<unsigned char> encode_push_promise(
    std::uint64_t push_id,
    std::vector<std::pair<std::string, std::string>> const& fields) {
    auto encoded = encode_fields(fields);
    auto const encoded_id = encode_varint(push_id);
    if(encoded.size() < 3 || encoded[0] != 0x01 || encoded[1] > 62)
        return {};
    std::vector<unsigned char> frame {
        0x05, static_cast<unsigned char>(encoded[1] + encoded_id.size())};
    frame.insert(frame.end(), encoded_id.begin(), encoded_id.end());
    frame.insert(frame.end(), encoded.begin() + 2, encoded.end());
    return frame;
}

} // namespace

TEST(H3Capture, ReassemblesFrameAndDecodesQpackHeaders) {
    sx::quic::h3_capture_decoder decoder;
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), 2).empty());
    auto records = decoder.ingest(
        socle::side_t::LEFT, 0, request.data() + 2, request.size() - 2);

    ASSERT_EQ(1U, records.size());
    EXPECT_EQ(socle::side_t::LEFT, records[0].side);
    EXPECT_EQ(0U, records[0].stream_id);
    ASSERT_EQ(4U, records[0].fields.size());
    EXPECT_EQ(":method", records[0].fields[0].name);
    EXPECT_EQ("GET", records[0].fields[0].value);
}

TEST(H3Capture, PreservesStaticNameWhileGrowingValueBuffer) {
    lsqpack_enc encoder {};
    std::array<unsigned char, LSQPACK_LONGEST_SDTC> capacity_instruction {};
    std::size_t capacity_size = capacity_instruction.size();
    ASSERT_EQ(0, lsqpack_enc_init(
        &encoder, nullptr, 0, 0, 0,
        static_cast<lsqpack_enc_opts>(0),
        capacity_instruction.data(), &capacity_size));
    ASSERT_EQ(0, lsqpack_enc_start_header(&encoder, 0, 0));

    std::array<unsigned char, 1> encoder_instructions {};
    auto const encode_flags = static_cast<lsqpack_enc_flags>(
        LQEF_NO_INDEX | LQEF_NO_DYN);
    std::vector<unsigned char> field_block_payload;
    for(auto const& [name, value]: std::vector<std::pair<std::string, std::string>>{
            {":method", "GET"}, {":scheme", "https"}, {":path", "/"},
            {":authority", "origin.runner.lab"}}) {
        std::string field_storage = name + value;
        lsxpack_header field {};
        lsxpack_header_set_offset2(&field, field_storage.data(), 0, name.size(),
                                   name.size(), value.size());
        std::array<unsigned char, 256> output {};
        std::size_t encoder_size = encoder_instructions.size();
        std::size_t output_size = output.size();
        ASSERT_EQ(LQES_OK, lsqpack_enc_encode(
            &encoder, encoder_instructions.data(), &encoder_size,
            output.data(), &output_size, &field, encode_flags));
        field_block_payload.insert(field_block_payload.end(), output.begin(),
                                   output.begin() + output_size);
    }

    std::array<unsigned char, 32> prefix {};
    lsqpack_enc_header_flags flags {};
    auto const prefix_size = lsqpack_enc_end_header(
        &encoder, prefix.data(), prefix.size(), &flags);
    ASSERT_GT(prefix_size, 0);
    lsqpack_enc_cleanup(&encoder);

    auto const field_section_size = static_cast<std::size_t>(prefix_size)
                                  + field_block_payload.size();
    ASSERT_LT(field_section_size, 64U);
    std::vector<unsigned char> request {
        0x01, static_cast<unsigned char>(field_section_size)};
    request.insert(request.end(), prefix.begin(), prefix.begin() + prefix_size);
    request.insert(request.end(), field_block_payload.begin(), field_block_payload.end());

    sx::quic::h3_capture_decoder decoder;
    auto records = decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size());

    ASSERT_EQ(1U, records.size());
    ASSERT_EQ(4U, records[0].fields.size());
    EXPECT_EQ(":authority", records[0].fields[3].name);
    EXPECT_EQ("origin.runner.lab", records[0].fields[3].value);
}

TEST(H3Capture, UnblocksHeadersFromQpackEncoderStream) {
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
    for(auto const& [name, value, flags]:
        std::vector<std::tuple<std::string, std::string, lsqpack_enc_flags>>{
            {":method", "GET", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {":scheme", "https", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {":authority", "fixture.example", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {":path", "/", static_cast<lsqpack_enc_flags>(LQEF_NO_DYN)},
            {"x-demo", "dynamic-value", static_cast<lsqpack_enc_flags>(0)}}) {
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

    std::vector<unsigned char> request {0x01};
    auto const field_section_size = static_cast<std::size_t>(prefix_size)
                                  + field_block_payload.size();
    ASSERT_LT(field_section_size, 64U);
    request.push_back(static_cast<unsigned char>(field_section_size));
    request.insert(request.end(), prefix.begin(), prefix.begin() + prefix_size);
    request.insert(request.end(), field_block_payload.begin(), field_block_payload.end());

    sx::quic::h3_capture_decoder decoder;
    // The server permits the client encoder to use a 4 KiB dynamic table and
    // at most sixteen blocked streams.
    const std::array<unsigned char, 8> server_qpack_settings {
        0x00, 0x04, 0x05, 0x01, 0x50, 0x00, 0x07, 0x10};
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 3, server_qpack_settings.data(),
        server_qpack_settings.size()).empty());
    constexpr std::size_t retained_block_limit = 8;
    for(std::size_t index = 0; index < retained_block_limit + 1; ++index) {
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, index * 4,
            request.data(), request.size()).empty());
    }

    std::vector<unsigned char> encoder_stream {0x02};
    encoder_stream.insert(encoder_stream.end(), capacity_instruction.begin(),
                          capacity_instruction.begin() + capacity_size);
    encoder_stream.insert(encoder_stream.end(), encoder_instructions.begin(),
                          encoder_instructions.begin() + encoder_size);
    auto records = decoder.ingest(
        socle::side_t::LEFT, 2, encoder_stream.data(), encoder_stream.size());
    lsqpack_enc_cleanup(&encoder);

    ASSERT_EQ(retained_block_limit, records.size());
    for(auto const& record : records) {
        ASSERT_EQ(5U, record.fields.size());
        EXPECT_EQ("x-demo", record.fields[4].name);
        EXPECT_EQ("dynamic-value", record.fields[4].value);
    }

    // The ninth blocked section exceeded the local retention bound. It must
    // remain a terminally abandoned semantic stream rather than letting a
    // later static field section masquerade as its request/trailers.
    auto const abandoned_followup = encode_fields({{"x-late", "forged"}});
    ASSERT_FALSE(abandoned_followup.empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, retained_block_limit * 4,
        abandoned_followup.data(), abandoned_followup.size()).empty());

    // The encoder stream bytes are a state transition, not an idempotent
    // snapshot. Reusing the same dynamic reference on a later request must
    // still resolve against exactly one applied insertion.
    auto later = decoder.ingest(
        socle::side_t::LEFT, 40, request.data(), request.size());
    ASSERT_EQ(1U, later.size());
    ASSERT_EQ(5U, later[0].fields.size());
    EXPECT_EQ("x-demo", later[0].fields[4].name);
    EXPECT_EQ("dynamic-value", later[0].fields[4].value);

    // With the default (zero) peer capacity, the same dynamic encoder state
    // is a connection error and later static headers cannot regain semantics.
    sx::quic::h3_capture_decoder zero_capacity_decoder;
    EXPECT_TRUE(zero_capacity_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    EXPECT_TRUE(zero_capacity_decoder.ingest(
        socle::side_t::LEFT, 2, encoder_stream.data(),
        encoder_stream.size()).empty());
    auto const static_request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/late"}});
    ASSERT_FALSE(static_request.empty());
    EXPECT_TRUE(zero_capacity_decoder.ingest(
        socle::side_t::LEFT, 4, static_request.data(),
        static_request.size()).empty());

    // A second encoder stream is a connection error. No later bytes on the
    // already invalid HTTP/3 connection may acquire inspection semantics.
    sx::quic::h3_capture_decoder duplicate_decoder;
    EXPECT_TRUE(duplicate_decoder.ingest(
        socle::side_t::RIGHT, 3, server_qpack_settings.data(),
        server_qpack_settings.size()).empty());
    const unsigned char encoder_type = 0x02;
    EXPECT_TRUE(duplicate_decoder.ingest(
        socle::side_t::LEFT, 2, &encoder_type, 1).empty());
    EXPECT_TRUE(duplicate_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    EXPECT_TRUE(duplicate_decoder.ingest(
        socle::side_t::LEFT, 6, encoder_stream.data(),
        encoder_stream.size()).empty());

    std::vector<unsigned char> legitimate_instructions;
    legitimate_instructions.insert(
        legitimate_instructions.end(), capacity_instruction.begin(),
        capacity_instruction.begin() + capacity_size);
    legitimate_instructions.insert(
        legitimate_instructions.end(), encoder_instructions.begin(),
        encoder_instructions.begin() + encoder_size);
    auto legitimate = duplicate_decoder.ingest(
        socle::side_t::LEFT, 2, legitimate_instructions.data(),
        legitimate_instructions.size());
    EXPECT_TRUE(legitimate.empty());

    sx::quic::h3_capture_decoder wrong_initiator_decoder;
    EXPECT_TRUE(wrong_initiator_decoder.ingest(
        socle::side_t::RIGHT, 3, server_qpack_settings.data(),
        server_qpack_settings.size()).empty());
    EXPECT_TRUE(wrong_initiator_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    EXPECT_TRUE(wrong_initiator_decoder.ingest(
        socle::side_t::LEFT, 3, encoder_stream.data(),
        encoder_stream.size()).empty());
    auto correctly_initiated = wrong_initiator_decoder.ingest(
        socle::side_t::LEFT, 2, encoder_stream.data(),
        encoder_stream.size());
    EXPECT_TRUE(correctly_initiated.empty());
}

TEST(H3Capture, RejectsDuplicateCriticalAndClientPushStreams) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    // Control and QPACK decoder streams are just as unique as the QPACK
    // encoder stream. They are not otherwise consumed by this observer, but
    // duplicates still invalidate the HTTP/3 connection.
    for(unsigned char const stream_type : {0x00, 0x03}) {
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 2, &stream_type, 1).empty());
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 6, &stream_type, 1).empty());
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    }

    // Push streams are server-initiated only. A client-originated one is a
    // connection error, even though its contents are irrelevant to request
    // header inspection.
    sx::quic::h3_capture_decoder client_push_decoder;
    const unsigned char push_stream_type = 0x01;
    EXPECT_TRUE(client_push_decoder.ingest(
        socle::side_t::LEFT, 2, &push_stream_type, 1).empty());
    EXPECT_TRUE(client_push_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).empty());
}

TEST(H3Capture, EnforcesControlStreamFrameSequence) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    for(auto const& invalid_control : std::vector<std::vector<unsigned char>>{
            {0x00, 0x07, 0x00},             // GOAWAY before SETTINGS
            {0x00, 0x04, 0x00, 0x04, 0x00}, // duplicate SETTINGS
            {0x00, 0x04, 0x00, 0x00, 0x00}, // DATA on control stream
            {0x00, 0x04, 0x00, 0x01, 0x00}, // HEADERS on control stream
            {0x00, 0x04, 0x00, 0x05, 0x00}, // PUSH_PROMISE on control stream
        }) {
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 2, invalid_control.data(),
            invalid_control.size()).empty());
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    }

    // Fragmented control framing remains valid. Unknown extension frames are
    // permitted after the mandatory SETTINGS and must not poison requests.
    sx::quic::h3_capture_decoder valid_decoder;
    const unsigned char control_type = 0x00;
    const unsigned char settings_type = 0x04;
    const std::array<unsigned char, 4> settings_tail_and_extension {
        0x00, 0x21, 0x01, 0x00};
    EXPECT_TRUE(valid_decoder.ingest(
        socle::side_t::LEFT, 2, &control_type, 1).empty());
    EXPECT_TRUE(valid_decoder.ingest(
        socle::side_t::LEFT, 2, &settings_type, 1).empty());
    EXPECT_TRUE(valid_decoder.ingest(
        socle::side_t::LEFT, 2, settings_tail_and_extension.data(),
        settings_tail_and_extension.size()).empty());
    EXPECT_EQ(valid_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
}

TEST(H3Capture, RejectsReservedHttp2FrameTypes) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    for(unsigned char const frame_type : {0x02, 0x06, 0x08, 0x09}) {
        // Reserved frame types are connection errors even when their payload
        // is empty and they occur on an otherwise valid request stream.
        sx::quic::h3_capture_decoder request_decoder;
        const std::array<unsigned char, 2> reserved {frame_type, 0x00};
        EXPECT_TRUE(request_decoder.ingest(
            socle::side_t::LEFT, 0, reserved.data(), reserved.size()).empty());
        EXPECT_TRUE(request_decoder.ingest(
            socle::side_t::LEFT, 4, request.data(), request.size()).empty());

        // They remain forbidden after the mandatory control-stream SETTINGS;
        // they are not greased extension frames that may be ignored.
        sx::quic::h3_capture_decoder control_decoder;
        const std::array<unsigned char, 5> control {
            0x00, 0x04, 0x00, frame_type, 0x00};
        EXPECT_TRUE(control_decoder.ingest(
            socle::side_t::LEFT, 2, control.data(), control.size()).empty());
        EXPECT_TRUE(control_decoder.ingest(
            socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    }
}

TEST(H3Capture, ValidatesControlFramePayloadsAndDirection) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    struct malformed_control {
        socle::side_t side;
        std::uint64_t stream_id;
        std::vector<unsigned char> bytes;
    };
    const std::vector<malformed_control> malformed {
        {socle::side_t::LEFT, 2, {0x00, 0x04, 0x00, 0x07, 0x00}},
        {socle::side_t::RIGHT, 3, {0x00, 0x04, 0x00, 0x07, 0x01, 0x01}},
        {socle::side_t::LEFT, 2,
         {0x00, 0x04, 0x00, 0x07, 0x01, 0x05, 0x07, 0x01, 0x06}},
        {socle::side_t::LEFT, 2,
         {0x00, 0x04, 0x00, 0x0d, 0x01, 0x05, 0x0d, 0x01, 0x04}},
        {socle::side_t::LEFT, 2,
         {0x00, 0x04, 0x00, 0x03, 0x01, 0x00}},
        {socle::side_t::LEFT, 2,
         {0x00, 0x04, 0x00, 0x0d, 0x01, 0x00, 0x03, 0x01, 0x01}},
    };
    for(auto const& item: malformed) {
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(item.side, item.stream_id,
                                   item.bytes.data(), item.bytes.size()).empty());
        EXPECT_TRUE(decoder.ingest(socle::side_t::LEFT, 0, request.data(),
                                   request.size()).empty());
    }

    sx::quic::h3_capture_decoder valid;
    const std::vector<unsigned char> control {
        0x00, 0x04, 0x00,
        0x0d, 0x01, 0x04,
        0x07, 0x01, 0x04,
        0x07, 0x01, 0x03,
        0x03, 0x01, 0x04,
    };
    EXPECT_TRUE(valid.ingest(socle::side_t::LEFT, 2, control.data(),
                             control.size()).empty());
    EXPECT_EQ(valid.ingest(socle::side_t::LEFT, 0, request.data(),
                           request.size()).size(), 1U);

    // A server can cancel an allowed push. Its control direction uses the
    // maximum advertised by the client, and the promise itself may still be
    // reordered behind this frame at the observer.
    sx::quic::h3_capture_decoder server_cancel;
    const std::array<unsigned char, 6> client_permit {
        0x00, 0x04, 0x00, 0x0d, 0x01, 0x00,
    };
    const std::array<unsigned char, 6> server_cancel_zero {
        0x00, 0x04, 0x00, 0x03, 0x01, 0x00,
    };
    EXPECT_TRUE(server_cancel.ingest(
        socle::side_t::LEFT, 2, client_permit.data(),
        client_permit.size()).empty());
    EXPECT_TRUE(server_cancel.ingest(
        socle::side_t::RIGHT, 3, server_cancel_zero.data(),
        server_cancel_zero.size()).empty());
    EXPECT_EQ(server_cancel.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
}

TEST(H3Capture, HonorsServerGoawayRequestBoundary) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    // Server GOAWAY=4 accepts request stream 0 but rejects stream 4 and all
    // later client-initiated bidirectional request streams.
    const std::array<unsigned char, 6> server_goaway {
        0x00, 0x04, 0x00, 0x07, 0x01, 0x04,
    };
    sx::quic::h3_capture_decoder decoder;
    EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 3,
                               server_goaway.data(),
                               server_goaway.size()).empty());
    EXPECT_EQ(decoder.ingest(socle::side_t::LEFT, 0,
                             request.data(), request.size()).size(), 1U);
    EXPECT_TRUE(decoder.ingest(socle::side_t::LEFT, 4,
                               request.data(), request.size()).empty());
}

TEST(H3Capture, DiscardsPushesBeyondClientGoawayBoundary) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const response = encode_fields({{":status", "200"}});
    auto const first_promise = encode_push_promise(0, {
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "push.example"}, {":path", "/first"}});
    auto const conflicting_promise = encode_push_promise(0, {
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "push.example"}, {":path", "/second"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(response.empty());
    ASSERT_FALSE(first_promise.empty());
    ASSERT_FALSE(conflicting_promise.empty());

    // Client permits Push ID 0, then GOAWAY=0 rejects that ID and every later
    // push. Rejected field sections still pass through QPACK decoding, but
    // their apparent conflict cannot poison an unrelated final response.
    const std::array<unsigned char, 9> client_control {
        0x00, 0x04, 0x00,
        0x0d, 0x01, 0x00,
        0x07, 0x01, 0x00,
    };
    sx::quic::h3_capture_decoder decoder;
    EXPECT_TRUE(decoder.ingest(socle::side_t::LEFT, 2,
                               client_control.data(),
                               client_control.size()).empty());
    ASSERT_EQ(decoder.ingest(socle::side_t::LEFT, 0,
                             request.data(), request.size()).size(), 1U);
    EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 0,
                               first_promise.data(),
                               first_promise.size()).empty());
    EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 0,
                               conflicting_promise.data(),
                               conflicting_promise.size()).empty());
    EXPECT_EQ(decoder.ingest(socle::side_t::RIGHT, 0,
                             response.data(), response.size()).size(), 1U);
}

TEST(H3Capture, IgnoresUnknownFramesBeforeInitialHeaders) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "fixture.example"},
        {":path", "/after-extension"}});
    ASSERT_FALSE(request.empty());

    const std::array<unsigned char, 4> extension {
        0x21, 0x02, 0xaa, 0xbb,
    };
    sx::quic::h3_capture_decoder decoder;
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 0, extension.data(), extension.size()).empty());
    auto records = decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size());
    ASSERT_EQ(records.size(), 1U);
    auto const path = std::find_if(
        records.front().fields.begin(), records.front().fields.end(),
        [](sx::quic::h3_header_field const& field) {
            return field.name == ":path";
        });
    ASSERT_NE(path, records.front().fields.end());
    EXPECT_EQ(path->value, "/after-extension");
}

TEST(H3Capture, ValidatesAndSynchronizesPushPromises) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const response = encode_fields({{":status", "200"}});
    auto const promise = encode_push_promise(0, {
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "push.example"}, {":path", "/asset"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(response.empty());
    ASSERT_FALSE(promise.empty());

    sx::quic::h3_capture_decoder valid;
    const std::array<unsigned char, 6> permit_push {
        0x00,       // client control stream type
        0x04, 0x00, // mandatory empty SETTINGS
        0x0d, 0x01, 0x00, // MAX_PUSH_ID = 0
    };
    EXPECT_TRUE(valid.ingest(socle::side_t::LEFT, 2, permit_push.data(),
                             permit_push.size()).empty());
    ASSERT_EQ(valid.ingest(socle::side_t::LEFT, 0, request.data(),
                           request.size()).size(), 1U);
    EXPECT_TRUE(valid.ingest(socle::side_t::RIGHT, 0, promise.data(),
                             promise.size()).empty());
    EXPECT_EQ(valid.ingest(socle::side_t::RIGHT, 0, response.data(),
                           response.size()).size(), 1U);

    for(auto const& invalid_promise: std::vector<std::vector<unsigned char>>{
            {0x05, 0x00},
            encode_push_promise(1, {
                {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}}),
            encode_push_promise(0, {
                {":method", "GET"}, {":scheme", "https"},
                {":path", "/host-fallback"}, {"host", "push.example"}}),
        }) {
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(socle::side_t::LEFT, 2, permit_push.data(),
                                   permit_push.size()).empty());
        ASSERT_EQ(decoder.ingest(socle::side_t::LEFT, 0, request.data(),
                                 request.size()).size(), 1U);
        EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 0,
                                   invalid_promise.data(),
                                   invalid_promise.size()).empty());
        EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 0, response.data(),
                                   response.size()).empty());
    }

    sx::quic::h3_capture_decoder duplicate;
    EXPECT_TRUE(duplicate.ingest(socle::side_t::LEFT, 2, permit_push.data(),
                                 permit_push.size()).empty());
    ASSERT_EQ(duplicate.ingest(socle::side_t::LEFT, 0, request.data(),
                               request.size()).size(), 1U);
    EXPECT_TRUE(duplicate.ingest(socle::side_t::RIGHT, 0, promise.data(),
                                 promise.size()).empty());
    ASSERT_EQ(duplicate.ingest(socle::side_t::LEFT, 4, request.data(),
                               request.size()).size(), 1U);
    EXPECT_TRUE(duplicate.ingest(socle::side_t::RIGHT, 4, promise.data(),
                                 promise.size()).empty());
    EXPECT_EQ(duplicate.ingest(socle::side_t::RIGHT, 0, response.data(),
                               response.size()).size(), 1U);

    auto const conflicting_promise = encode_push_promise(0, {
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "push.example"}, {":path", "/different"}});
    ASSERT_FALSE(conflicting_promise.empty());
    sx::quic::h3_capture_decoder conflicting;
    EXPECT_TRUE(conflicting.ingest(socle::side_t::LEFT, 2, permit_push.data(),
                                   permit_push.size()).empty());
    ASSERT_EQ(conflicting.ingest(socle::side_t::LEFT, 0, request.data(),
                                 request.size()).size(), 1U);
    EXPECT_TRUE(conflicting.ingest(socle::side_t::RIGHT, 0, promise.data(),
                                   promise.size()).empty());
    ASSERT_EQ(conflicting.ingest(socle::side_t::LEFT, 4, request.data(),
                                 request.size()).size(), 1U);
    EXPECT_TRUE(conflicting.ingest(socle::side_t::RIGHT, 4,
                                   conflicting_promise.data(),
                                   conflicting_promise.size()).empty());
    EXPECT_TRUE(conflicting.ingest(socle::side_t::RIGHT, 0, response.data(),
                                   response.size()).empty());
}

TEST(H3Capture, BoundsTrackedPushPromises) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "fixture.example"}, {":path", "/"}});
    auto const response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(response.empty());

    // MAX_PUSH_ID = 64. A single associated request stream must not be able
    // to grow retained promised-push state without a small independent bound.
    const std::array<unsigned char, 7> permit_push_64 {
        0x00, 0x04, 0x00, 0x0d, 0x02, 0x40, 0x40,
    };
    sx::quic::h3_capture_decoder decoder;
    EXPECT_TRUE(decoder.ingest(socle::side_t::LEFT, 2,
                               permit_push_64.data(),
                               permit_push_64.size()).empty());
    ASSERT_EQ(decoder.ingest(socle::side_t::LEFT, 0, request.data(),
                             request.size()).size(), 1U);

    for(std::uint64_t push_id = 0; push_id < 64; ++push_id) {
        auto const promise = encode_push_promise(push_id, {
            {":method", "GET"}, {":scheme", "https"},
            {":authority", "push.example"}, {":path", "/asset"}});
        ASSERT_FALSE(promise.empty());
        (void)decoder.ingest(socle::side_t::RIGHT, 0, promise.data(),
                             promise.size());
    }

    auto const overflow = encode_push_promise(64, {
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "push.example"}, {":path", "/overflow"}});
    ASSERT_FALSE(overflow.empty());
    EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 0, overflow.data(),
                               overflow.size()).empty());
    EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 0, response.data(),
                               response.size()).empty());
}

TEST(H3Capture, ValidatesServerPushStreamIdentifiers) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(response.empty());

    const std::array<unsigned char, 7> permit_push_64 {
        0x00, 0x04, 0x00,       // control stream and empty SETTINGS
        0x0d, 0x02, 0x40, 0x40, // MAX_PUSH_ID = 64
    };
    sx::quic::h3_capture_decoder valid;
    EXPECT_TRUE(valid.ingest(socle::side_t::LEFT, 2, permit_push_64.data(),
                             permit_push_64.size()).empty());
    ASSERT_EQ(valid.ingest(socle::side_t::LEFT, 0, request.data(),
                           request.size()).size(), 1U);
    const std::array<unsigned char, 2> split_push_start {0x01, 0x40};
    const unsigned char split_push_end = 0x40;
    EXPECT_TRUE(valid.ingest(socle::side_t::RIGHT, 3,
                             split_push_start.data(),
                             split_push_start.size()).empty());
    EXPECT_TRUE(valid.ingest(socle::side_t::RIGHT, 3,
                             &split_push_end, 1).empty());
    EXPECT_EQ(valid.ingest(socle::side_t::RIGHT, 0, response.data(),
                           response.size()).size(), 1U);

    auto expect_connection_error = [&](bool advertise,
                                       std::vector<unsigned char> push,
                                       bool duplicate) {
        sx::quic::h3_capture_decoder decoder;
        if(advertise) {
            EXPECT_TRUE(decoder.ingest(socle::side_t::LEFT, 2,
                                       permit_push_64.data(),
                                       permit_push_64.size()).empty());
        }
        ASSERT_EQ(decoder.ingest(socle::side_t::LEFT, 0, request.data(),
                                 request.size()).size(), 1U);
        push.insert(push.begin(), 0x01);
        EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 3, push.data(),
                                   push.size()).empty());
        if(duplicate) {
            EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 7, push.data(),
                                       push.size()).empty());
        }
        EXPECT_TRUE(decoder.ingest(socle::side_t::RIGHT, 0, response.data(),
                                   response.size()).empty());
    };
    expect_connection_error(false, {0x00}, false); // no MAX_PUSH_ID
    expect_connection_error(true, {0x40, 0x41}, false); // 65 > 64
    expect_connection_error(true, {0x00}, true); // duplicate push stream ID
}

TEST(H3Capture, ValidatesSettingsPayloadIncrementally) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    for(auto const& invalid_settings : std::vector<std::vector<unsigned char>>{
            {0x00, 0x04, 0x04, 0x01, 0x00, 0x01, 0x00}, // duplicate identifier
            {0x00, 0x04, 0x02, 0x02, 0x00},             // HTTP/2 setting id
            {0x00, 0x04, 0x02, 0x08, 0x02},             // boolean > 1
            {0x00, 0x04, 0x02, 0x33, 0x02},             // H3_DATAGRAM > 1
            {0x00, 0x04, 0x01, 0x01},                   // missing value
        }) {
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 2, invalid_settings.data(),
            invalid_settings.size()).empty());
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    }

    sx::quic::h3_capture_decoder valid_decoder;
    const std::array<unsigned char, 4> first {0x00, 0x04, 0x04, 0x01};
    const std::array<unsigned char, 3> second {0x00, 0x06, 0x00};
    EXPECT_TRUE(valid_decoder.ingest(
        socle::side_t::LEFT, 2, first.data(), first.size()).empty());
    EXPECT_TRUE(valid_decoder.ingest(
        socle::side_t::LEFT, 2, second.data(), second.size()).empty());
    EXPECT_EQ(valid_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
}

TEST(H3Capture, RejectsHttp3HeaderSemanticViolations) {
    const std::vector<std::vector<std::pair<std::string, std::string>>> malformed {
        {{"X-Test", "value"}},
        {{"x-test", "value"}, {":method", "GET"}},
        {{":method", "GET"}, {":method", "POST"}},
        {{":method", "GET"}, {":path", "/"}},
        {{":method", "GET"}, {":scheme", "https"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}},
        {{":method", "G ET"}, {":scheme", "https"}, {":path", "/"}},
        {{":method", "GET"}, {":scheme", "1https"}, {":path", "/"}},
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "relative"}},
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/raw path"}},
        {{":method", "GET"}, {":scheme", "https"},
         {":path", "/fragment#hidden"}},
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "*"}},
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
         {":protocol", "websocket"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
         {":authority", "allowed.example\tevil"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
         {":authority", "allowed.example/path"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
         {":authority", "[not-ipv6]:443"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
         {":authority", "allowed.example:443junk"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
         {"host", "first.example"}, {"host", "second.example"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
         {":authority", "inspected.example"}, {"host", "forwarded.example"}},
        {{":method", "GET"}, {":scheme", "https"}, {":authority", ""},
         {":path", "/"}, {"host", "fallback.example"}},
        {{":method", "CONNECT"}, {":scheme", "https"},
         {":authority", "example.test"}, {":path", "/chat"},
         {":protocol", "web socket"}},
        {{":method", "CONNECT"}},
        {{":method", "CONNECT"}, {":authority", "example.test"},
         {":scheme", "https"}},
        {{":status", "200"}},
        {{":status", "20"}},
        {{":status", "2x0"}},
        {{":status", "099"}},
        {{":status", "600"}},
        {{"connection", "close"}},
        {{"te", "gzip"}},
        {{"x-test", "a\rb"}},
        {{"x-test", std::string("a\x01" "b", 3)}},
        {{"x-test", std::string("a\x7f" "b", 3)}},
        {{"x-test", " value"}},
    };

    for(auto const& fields: malformed) {
        auto const frame = encode_fields(fields);
        ASSERT_FALSE(frame.empty());
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 0, frame.data(), frame.size()).empty());
    }

    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
        {"te", "trailers"}});
    ASSERT_FALSE(request.empty());
    sx::quic::h3_capture_decoder request_decoder;
    EXPECT_EQ(request_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1u);

    auto const mixed_case_te = encode_fields({
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "fixture.example"}, {":path", "/"},
        {"te", "TrAiLeRs"}});
    ASSERT_FALSE(mixed_case_te.empty());
    sx::quic::h3_capture_decoder mixed_case_te_decoder;
    EXPECT_EQ(mixed_case_te_decoder.ingest(
        socle::side_t::LEFT, 0, mixed_case_te.data(), mixed_case_te.size()).size(),
        1u);

    auto const ipv6_request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":path", "/"},
        {":authority", "[2001:db8::1]:443"}});
    ASSERT_FALSE(ipv6_request.empty());
    sx::quic::h3_capture_decoder ipv6_decoder;
    EXPECT_EQ(ipv6_decoder.ingest(
        socle::side_t::LEFT, 0, ipv6_request.data(), ipv6_request.size()).size(),
        1u);

    auto const matching_authorities = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":path", "/"},
        {":authority", "same.example"}, {"host", "same.example"}});
    ASSERT_FALSE(matching_authorities.empty());
    sx::quic::h3_capture_decoder matching_authorities_decoder;
    EXPECT_EQ(matching_authorities_decoder.ingest(
        socle::side_t::LEFT, 0, matching_authorities.data(),
        matching_authorities.size()).size(), 1u);

    auto const case_equivalent_authorities = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":path", "/"},
        {":authority", "Case.Example:443"}, {"host", "case.example:443"}});
    ASSERT_FALSE(case_equivalent_authorities.empty());
    sx::quic::h3_capture_decoder case_equivalent_decoder;
    EXPECT_EQ(case_equivalent_decoder.ingest(
        socle::side_t::LEFT, 0, case_equivalent_authorities.data(),
        case_equivalent_authorities.size()).size(), 1u);

    auto const options = encode_fields({
        {":method", "OPTIONS"}, {":scheme", "https"},
        {":authority", "fixture.example"}, {":path", "*"}});
    ASSERT_FALSE(options.empty());
    sx::quic::h3_capture_decoder options_decoder;
    EXPECT_EQ(options_decoder.ingest(
        socle::side_t::LEFT, 0, options.data(), options.size()).size(), 1u);

    auto const response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(response.empty());
    EXPECT_EQ(request_decoder.ingest(
        socle::side_t::RIGHT, 0, response.data(), response.size()).size(), 1u);

    auto const switching_protocols = encode_fields({{":status", "101"}});
    ASSERT_FALSE(switching_protocols.empty());
    sx::quic::h3_capture_decoder switching_decoder;
    EXPECT_EQ(switching_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1u);
    EXPECT_TRUE(switching_decoder.ingest(
        socle::side_t::RIGHT, 0, switching_protocols.data(),
        switching_protocols.size()).empty());

    sx::quic::h3_capture_decoder unsolicited_response_decoder;
    EXPECT_TRUE(unsolicited_response_decoder.ingest(
        socle::side_t::RIGHT, 0, response.data(), response.size()).empty());
    auto reordered = unsolicited_response_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size());
    ASSERT_EQ(reordered.size(), 2U);
    EXPECT_EQ(reordered[0].side, socle::side_t::LEFT);
    EXPECT_EQ(reordered[1].side, socle::side_t::RIGHT);
    EXPECT_EQ(reordered[1].stream_id, 0U);

    auto const connect = encode_fields({
        {":method", "CONNECT"}, {":authority", "example.test"}});
    ASSERT_FALSE(connect.empty());
    sx::quic::h3_capture_decoder connect_decoder;
    EXPECT_EQ(connect_decoder.ingest(
        socle::side_t::LEFT, 0, connect.data(), connect.size()).size(), 1u);

    auto const extended_connect = encode_fields({
        {":method", "CONNECT"}, {":scheme", "https"},
        {":authority", "example.test"}, {":path", "/chat"},
        {":protocol", "websocket"}});
    ASSERT_FALSE(extended_connect.empty());
    sx::quic::h3_capture_decoder extended_decoder;
    EXPECT_TRUE(extended_decoder.ingest(
        socle::side_t::LEFT, 0, extended_connect.data(),
        extended_connect.size()).empty());

    sx::quic::h3_capture_decoder enabled_extended_decoder;
    const std::array<unsigned char, 5> enable_extended_connect {
        0x00,       // control stream type
        0x04, 0x02, // SETTINGS frame, two-byte payload
        0x08, 0x01, // SETTINGS_ENABLE_CONNECT_PROTOCOL = 1
    };
    EXPECT_TRUE(enabled_extended_decoder.ingest(
        socle::side_t::RIGHT, 3, enable_extended_connect.data(),
        enable_extended_connect.size()).empty());
    EXPECT_EQ(enabled_extended_decoder.ingest(
        socle::side_t::LEFT, 0, extended_connect.data(),
        extended_connect.size()).size(), 1U);

    auto const trailer = encode_fields({{"x-checksum", "ok"}});
    ASSERT_FALSE(trailer.empty());
    auto trailer_records = request_decoder.ingest(
        socle::side_t::LEFT, 0, trailer.data(), trailer.size());
    ASSERT_EQ(1U, trailer_records.size());
    EXPECT_EQ("x-checksum", trailer_records[0].fields[0].name);

    auto const pseudo_trailer = encode_fields({{":path", "/late"}});
    ASSERT_FALSE(pseudo_trailer.empty());
    EXPECT_TRUE(request_decoder.ingest(
        socle::side_t::LEFT, 0, pseudo_trailer.data(),
        pseudo_trailer.size()).empty());
}

TEST(H3Capture, RejectsAmbiguousHttp3ContentLength) {
    const std::vector<std::vector<std::pair<std::string, std::string>>> malformed {
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
         {"content-length", "12x"}},
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
         {"content-length", "+12"}},
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
         {"content-length", "12"}, {"content-length", "13"}},
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
         {"content-length", "18446744073709551616"}},
    };
    for(auto const& fields: malformed) {
        auto const frame = encode_fields(fields);
        ASSERT_FALSE(frame.empty());
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 0, frame.data(), frame.size()).empty());
    }

    for(auto const& fields:
        std::vector<std::vector<std::pair<std::string, std::string>>>{
            {{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
             {"content-length", "12"}, {"content-length", "12"}},
            {{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
             {"content-length", "12, 12"}},
        }) {
        auto const frame = encode_fields(fields);
        ASSERT_FALSE(frame.empty());
        sx::quic::h3_capture_decoder decoder;
        EXPECT_EQ(decoder.ingest(
            socle::side_t::LEFT, 0, frame.data(), frame.size()).size(), 1U);
    }

    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());

    sx::quic::h3_capture_decoder response_decoder;
    ASSERT_EQ(response_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
    auto const invalid_response = encode_fields(
        {{":status", "204"}, {"content-length", "0"}});
    ASSERT_FALSE(invalid_response.empty());
    EXPECT_TRUE(response_decoder.ingest(
        socle::side_t::RIGHT, 0, invalid_response.data(),
        invalid_response.size()).empty());

    sx::quic::h3_capture_decoder not_modified_decoder;
    ASSERT_EQ(not_modified_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
    auto const not_modified = encode_fields(
        {{":status", "304"}, {"content-length", "123"}});
    ASSERT_FALSE(not_modified.empty());
    EXPECT_EQ(not_modified_decoder.ingest(
        socle::side_t::RIGHT, 0, not_modified.data(),
        not_modified.size()).size(), 1U);

    sx::quic::h3_capture_decoder invalid_reset_decoder;
    ASSERT_EQ(invalid_reset_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
    auto const invalid_reset = encode_fields(
        {{":status", "205"}, {"content-length", "1"}});
    ASSERT_FALSE(invalid_reset.empty());
    EXPECT_TRUE(invalid_reset_decoder.ingest(
        socle::side_t::RIGHT, 0, invalid_reset.data(),
        invalid_reset.size()).empty());

    sx::quic::h3_capture_decoder empty_reset_decoder;
    ASSERT_EQ(empty_reset_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
    auto const empty_reset = encode_fields(
        {{":status", "205"}, {"content-length", "0"}});
    ASSERT_FALSE(empty_reset.empty());
    EXPECT_EQ(empty_reset_decoder.ingest(
        socle::side_t::RIGHT, 0, empty_reset.data(),
        empty_reset.size()).size(), 1U);

    sx::quic::h3_capture_decoder trailer_decoder;
    ASSERT_EQ(trailer_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
    auto const invalid_trailer = encode_fields({{"content-length", "0"}});
    ASSERT_FALSE(invalid_trailer.empty());
    EXPECT_TRUE(trailer_decoder.ingest(
        socle::side_t::LEFT, 0, invalid_trailer.data(),
        invalid_trailer.size()).empty());
}

TEST(H3Capture, RejectsHttp3DataBeyondDeclaredOrForbiddenBodies) {
    auto const overlong_request = encode_fields({
        {":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
        {"content-length", "2"}});
    auto const trailer = encode_fields({{"x-checksum", "ok"}});
    ASSERT_FALSE(overlong_request.empty());
    ASSERT_FALSE(trailer.empty());
    const std::array<unsigned char, 5> three_bytes {0x00, 0x03, 'a', 'b', 'c'};

    sx::quic::h3_capture_decoder overlong_decoder;
    ASSERT_EQ(overlong_decoder.ingest(
        socle::side_t::LEFT, 0, overlong_request.data(),
        overlong_request.size()).size(), 1U);
    EXPECT_TRUE(overlong_decoder.ingest(
        socle::side_t::LEFT, 0, three_bytes.data(),
        three_bytes.size()).empty());
    EXPECT_TRUE(overlong_decoder.ingest(
        socle::side_t::LEFT, 0, trailer.data(), trailer.size()).empty());

    auto const exact_request = encode_fields({
        {":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"},
        {"content-length", "3"}});
    ASSERT_FALSE(exact_request.empty());
    sx::quic::h3_capture_decoder exact_decoder;
    ASSERT_EQ(exact_decoder.ingest(
        socle::side_t::LEFT, 0, exact_request.data(),
        exact_request.size()).size(), 1U);
    EXPECT_TRUE(exact_decoder.ingest(
        socle::side_t::LEFT, 0, three_bytes.data(),
        three_bytes.size()).empty());
    EXPECT_EQ(exact_decoder.ingest(
        socle::side_t::LEFT, 0, trailer.data(), trailer.size()).size(), 1U);

    sx::quic::h3_capture_decoder short_decoder;
    ASSERT_EQ(short_decoder.ingest(
        socle::side_t::LEFT, 0, exact_request.data(),
        exact_request.size()).size(), 1U);
    const std::array<unsigned char, 4> two_bytes {0x00, 0x02, 'a', 'b'};
    EXPECT_TRUE(short_decoder.ingest(
        socle::side_t::LEFT, 0, two_bytes.data(), two_bytes.size()).empty());
    EXPECT_TRUE(short_decoder.ingest(
        socle::side_t::LEFT, 0, trailer.data(), trailer.size()).empty());

    auto const get_request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const not_modified = encode_fields(
        {{":status", "304"}, {"content-length", "10"}});
    ASSERT_FALSE(get_request.empty());
    ASSERT_FALSE(not_modified.empty());
    sx::quic::h3_capture_decoder forbidden_decoder;
    ASSERT_EQ(forbidden_decoder.ingest(
        socle::side_t::LEFT, 0, get_request.data(), get_request.size()).size(), 1U);
    ASSERT_EQ(forbidden_decoder.ingest(
        socle::side_t::RIGHT, 0, not_modified.data(),
        not_modified.size()).size(), 1U);
    const std::array<unsigned char, 3> one_byte {0x00, 0x01, 'x'};
    EXPECT_TRUE(forbidden_decoder.ingest(
        socle::side_t::RIGHT, 0, one_byte.data(), one_byte.size()).empty());
    EXPECT_TRUE(forbidden_decoder.ingest(
        socle::side_t::RIGHT, 0, trailer.data(), trailer.size()).empty());
}

TEST(H3Capture, EnforcesRequestMethodSpecificResponseBodies) {
    auto const head_request = encode_fields({
        {":method", "HEAD"}, {":scheme", "https"},
        {":authority", "fixture.example"}, {":path", "/"}});
    auto const ok_response = encode_fields({{":status", "200"}});
    auto const trailer = encode_fields({{"x-checksum", "ok"}});
    ASSERT_FALSE(head_request.empty());
    ASSERT_FALSE(ok_response.empty());
    ASSERT_FALSE(trailer.empty());

    sx::quic::h3_capture_decoder head_decoder;
    ASSERT_EQ(head_decoder.ingest(
        socle::side_t::LEFT, 0, head_request.data(), head_request.size()).size(),
        1U);
    ASSERT_EQ(head_decoder.ingest(
        socle::side_t::RIGHT, 0, ok_response.data(), ok_response.size()).size(),
        1U);
    const std::array<unsigned char, 3> forbidden_data {0x00, 0x01, 'x'};
    EXPECT_TRUE(head_decoder.ingest(
        socle::side_t::RIGHT, 0, forbidden_data.data(),
        forbidden_data.size()).empty());
    EXPECT_TRUE(head_decoder.ingest(
        socle::side_t::RIGHT, 0, trailer.data(), trailer.size()).empty());

    auto const connect_request = encode_fields({
        {":method", "CONNECT"}, {":authority", "target.example:443"}});
    auto const connect_response = encode_fields(
        {{":status", "200"}, {"content-length", "0"}});
    ASSERT_FALSE(connect_request.empty());
    ASSERT_FALSE(connect_response.empty());
    sx::quic::h3_capture_decoder connect_decoder;
    ASSERT_EQ(connect_decoder.ingest(
        socle::side_t::LEFT, 0, connect_request.data(),
        connect_request.size()).size(), 1U);
    EXPECT_TRUE(connect_decoder.ingest(
        socle::side_t::RIGHT, 0, connect_response.data(),
        connect_response.size()).empty());

    // Capture callbacks can deliver the response direction first. Retain the
    // same method-dependent verdict when the request arrives afterwards.
    sx::quic::h3_capture_decoder reordered_head_decoder;
    EXPECT_TRUE(reordered_head_decoder.ingest(
        socle::side_t::RIGHT, 0, ok_response.data(), ok_response.size()).empty());
    EXPECT_TRUE(reordered_head_decoder.ingest(
        socle::side_t::RIGHT, 0, forbidden_data.data(),
        forbidden_data.size()).empty());
    auto reordered_head = reordered_head_decoder.ingest(
        socle::side_t::LEFT, 0, head_request.data(), head_request.size());
    ASSERT_EQ(reordered_head.size(), 1U);
    EXPECT_EQ(reordered_head.front().side, socle::side_t::LEFT);

    sx::quic::h3_capture_decoder reordered_connect_decoder;
    EXPECT_TRUE(reordered_connect_decoder.ingest(
        socle::side_t::RIGHT, 0, connect_response.data(),
        connect_response.size()).empty());
    auto reordered_connect = reordered_connect_decoder.ingest(
        socle::side_t::LEFT, 0, connect_request.data(), connect_request.size());
    ASSERT_EQ(reordered_connect.size(), 1U);
    EXPECT_EQ(reordered_connect.front().side, socle::side_t::LEFT);
}

TEST(H3Capture, AcceptsInformationalResponsesBeforeFinalResponse) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const early = encode_fields({{":status", "103"}});
    auto const final_response = encode_fields({{":status", "200"}});
    auto const trailer = encode_fields({{"x-checksum", "ok"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(early.empty());
    ASSERT_FALSE(final_response.empty());
    ASSERT_FALSE(trailer.empty());

    sx::quic::h3_capture_decoder decoder;
    ASSERT_EQ(decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1u);

    auto early_records = decoder.ingest(
        socle::side_t::RIGHT, 0, early.data(), early.size());
    ASSERT_EQ(early_records.size(), 1u);
    EXPECT_EQ(early_records[0].fields[0].value, "103");

    auto final_records = decoder.ingest(
        socle::side_t::RIGHT, 0, final_response.data(), final_response.size());
    ASSERT_EQ(final_records.size(), 1u);
    EXPECT_EQ(final_records[0].fields[0].value, "200");

    auto trailer_records = decoder.ingest(
        socle::side_t::RIGHT, 0, trailer.data(), trailer.size());
    ASSERT_EQ(trailer_records.size(), 1u);
    EXPECT_EQ(trailer_records[0].fields[0].name, "x-checksum");
}

TEST(H3Capture, RejectsDataBetweenInformationalAndFinalResponse) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const informational = encode_fields({{":status", "103"}});
    auto const final_response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(informational.empty());
    ASSERT_FALSE(final_response.empty());

    sx::quic::h3_capture_decoder decoder;
    ASSERT_EQ(decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
    ASSERT_EQ(decoder.ingest(
        socle::side_t::RIGHT, 0, informational.data(),
        informational.size()).size(), 1U);

    const std::array<unsigned char, 3> premature_data {0x00, 0x01, 'x'};
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 0, premature_data.data(),
        premature_data.size()).empty());

    // The invalid sequence is H3_FRAME_UNEXPECTED, a connection error.  No
    // later bytes can regain semantics that a conforming endpoint discarded.
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 0, final_response.data(),
        final_response.size()).empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 4, request.data(), request.size()).empty());
}

TEST(H3Capture, MalformedHeadersRemainTerminalForTheirRequestStream) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const malformed_response = encode_fields({{":status", "20"}});
    auto const valid_response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(malformed_response.empty());
    ASSERT_FALSE(valid_response.empty());

    sx::quic::h3_capture_decoder decoder;
    ASSERT_EQ(decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1u);
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 0, malformed_response.data(),
        malformed_response.size()).empty());

    // The endpoint resets this request stream with H3_MESSAGE_ERROR.  A
    // syntactically valid block arriving afterwards must not resurrect it in
    // inspection, while unrelated streams remain usable.
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 0, valid_response.data(),
        valid_response.size()).empty());

    // A stream-scoped H3_MESSAGE_ERROR must not be escalated to a connection
    // error merely because more bytes arrive on the already rejected stream.
    const std::array<unsigned char, 3> post_error_data {0x00, 0x01, 'x'};
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 0, post_error_data.data(),
        post_error_data.size()).empty());

    ASSERT_EQ(decoder.ingest(
        socle::side_t::LEFT, 4, request.data(), request.size()).size(), 1u);
    EXPECT_EQ(decoder.ingest(
        socle::side_t::RIGHT, 4, valid_response.data(),
        valid_response.size()).size(), 1u);
}

TEST(H3Capture, OversizedHeadersTerminateOnlyTheirSemanticStream) {
    constexpr std::size_t oversized_length = 1024U * 1024U + 1U;
    std::vector<unsigned char> oversized {
        0x01,                   // HEADERS
        0x80, 0x10, 0x00, 0x01 // four-byte QUIC varint: 1 MiB + 1
    };
    oversized.resize(oversized.size() + oversized_length, 0);

    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(response.empty());

    sx::quic::h3_capture_decoder request_decoder;
    EXPECT_TRUE(request_decoder.ingest(
        socle::side_t::LEFT, 0, oversized.data(), oversized.size()).empty());
    EXPECT_TRUE(request_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    EXPECT_EQ(request_decoder.ingest(
        socle::side_t::LEFT, 4, request.data(), request.size()).size(), 1u);

    sx::quic::h3_capture_decoder response_decoder;
    ASSERT_EQ(response_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1u);
    EXPECT_TRUE(response_decoder.ingest(
        socle::side_t::RIGHT, 0, oversized.data(), oversized.size()).empty());
    EXPECT_TRUE(response_decoder.ingest(
        socle::side_t::RIGHT, 0, response.data(), response.size()).empty());
    ASSERT_EQ(response_decoder.ingest(
        socle::side_t::LEFT, 4, request.data(), request.size()).size(), 1u);
    EXPECT_EQ(response_decoder.ingest(
        socle::side_t::RIGHT, 4, response.data(), response.size()).size(), 1u);
}

TEST(H3Capture, RejectsServerInitiatedBidirectionalStreamsConnectionWide) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(response.empty());

    sx::quic::h3_capture_decoder decoder;
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 1, request.data(), request.size()).empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 1, response.data(), response.size()).empty());

    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 4, request.data(), request.size()).empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 4, response.data(), response.size()).empty());
}

TEST(H3Capture, RejectsInvalidRequestStreamFrameSequences) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const trailer = encode_fields({{"x-checksum", "ok"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(trailer.empty());

    for (auto const& prefix : std::vector<std::vector<unsigned char>>{
             {0x00, 0x00}, // DATA before initial HEADERS
             {0x04, 0x00}, // SETTINGS belongs on the control stream
             {0x05, 0x00}, // clients cannot send PUSH_PROMISE
         }) {
        sx::quic::h3_capture_decoder decoder;
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 0, prefix.data(), prefix.size()).empty());
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, 0, request.data(), request.size()).empty());
    }

    sx::quic::h3_capture_decoder trailers_decoder;
    EXPECT_EQ(trailers_decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).size(), 1U);
    EXPECT_EQ(trailers_decoder.ingest(
        socle::side_t::LEFT, 0, trailer.data(), trailer.size()).size(), 1U);
    EXPECT_TRUE(trailers_decoder.ingest(
        socle::side_t::LEFT, 0, trailer.data(), trailer.size()).empty());
}

TEST(H3Capture, ConnectionErrorsSuppressSemanticsOnEveryStream) {
    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    auto const response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(request.empty());
    ASSERT_FALSE(response.empty());

    sx::quic::h3_capture_decoder decoder;
    const std::array<unsigned char, 2> misplaced_settings {0x04, 0x00};
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 0, misplaced_settings.data(),
        misplaced_settings.size()).empty());

    // The error is connection-wide, not scoped to stream 0 or one direction.
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 4, request.data(), request.size()).empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 4, response.data(), response.size()).empty());
}

TEST(H3Capture, BoundsTheDecompressedQpackFieldList) {
    // QPACK prefix (Required Insert Count, Delta Base) followed by repeated
    // one-byte static references to :method GET. Each decoded field accounts
    // for 7 + 3 + 32 bytes, so this compact section crosses the 1 MiB output
    // budget without approaching the compressed-input limit.
    constexpr std::size_t field_size = 7 + 3 + 32;
    constexpr std::size_t count = (1024 * 1024) / field_size + 1;
    std::vector<unsigned char> section {0x00, 0x00};
    section.insert(section.end(), count, 0xD1);

    const auto length = static_cast<std::uint32_t>(section.size());
    ASSERT_LT(length, 1u << 30);
    std::vector<unsigned char> frame {
        0x01,
        static_cast<unsigned char>(0x80U | (length >> 24U)),
        static_cast<unsigned char>(length >> 16U),
        static_cast<unsigned char>(length >> 8U),
        static_cast<unsigned char>(length),
    };
    frame.insert(frame.end(), section.begin(), section.end());

    sx::quic::h3_capture_decoder decoder;
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 0, frame.data(), frame.size()).empty());
}

TEST(H3Capture, RejectsQpackCapacityBeyondInspectionBudget) {
    sx::quic::h3_capture_decoder decoder;
    // Server control stream, SETTINGS frame, QPACK_MAX_TABLE_CAPACITY =
    // 1 MiB + 1 encoded as a four-byte QUIC varint.
    const std::array<unsigned char, 8> oversized_settings {
        0x00, 0x04, 0x05, 0x01, 0x80, 0x10, 0x00, 0x01
    };
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, 3, oversized_settings.data(),
        oversized_settings.size()).empty());

    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"},
        {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).empty());
}

TEST(H3Capture, BoundsTrackedStreamState) {
    sx::quic::h3_capture_decoder decoder;
    const unsigned char incomplete_varint = 0xc0; // eight-byte frame type
    constexpr std::size_t stream_limit = 4096;
    for(std::size_t index = 0; index < stream_limit - 1; ++index) {
        EXPECT_TRUE(decoder.ingest(
            socle::side_t::LEFT, index * 4, &incomplete_varint, 1).empty());
    }

    auto const request = encode_fields({
        {":method", "GET"}, {":scheme", "https"}, {":authority", "fixture.example"}, {":path", "/"}});
    ASSERT_FALSE(request.empty());
    EXPECT_EQ(decoder.ingest(
        socle::side_t::LEFT, (stream_limit - 1) * 4,
        request.data(), request.size()).size(), 1u);
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, stream_limit * 4,
        request.data(), request.size()).empty());

    // Saturating ordinary request-stream state must not hide a duplicate
    // critical stream. The first control stream is admitted beyond the
    // ordinary bound; the second makes the connection terminal.
    const std::array<unsigned char, 3> control {
        0x00, // control stream type
        0x04, 0x00, // empty SETTINGS
    };
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 2, control.data(), control.size()).empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 6, control.data(), control.size()).empty());

    auto const response = encode_fields({{":status", "200"}});
    ASSERT_FALSE(response.empty());
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::RIGHT, (stream_limit - 1) * 4,
        response.data(), response.size()).empty());
}
