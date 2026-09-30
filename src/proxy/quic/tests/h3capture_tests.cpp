#include <gtest/gtest.h>

#include "proxy/quic/h3capture.hpp"

#include <lsqpack.h>
#include <lsxpack_header.h>

#include <array>
#include <string>
#include <vector>

TEST(H3Capture, ReassemblesFrameAndDecodesQpackHeaders) {
    sx::quic::h3_capture_decoder decoder;
    std::array<unsigned char, 5> const request {
        0x01, 0x03,       // H3 HEADERS frame, three-byte field section.
        0x00, 0x00, 0xD1 // QPACK :method = GET from the static table.
    };

    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), 2).empty());
    auto records = decoder.ingest(
        socle::side_t::LEFT, 0, request.data() + 2, request.size() - 2);

    ASSERT_EQ(1U, records.size());
    EXPECT_EQ(socle::side_t::LEFT, records[0].side);
    EXPECT_EQ(0U, records[0].stream_id);
    ASSERT_EQ(1U, records[0].fields.size());
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

    std::string const field_storage = ":authorityorigin.runner.lab";
    lsxpack_header field {};
    lsxpack_header_set_offset2(
        &field, field_storage.data(), 0, 10, 10, 17);
    std::array<unsigned char, 1> encoder_instructions {};
    std::array<unsigned char, 256> field_block_payload {};
    std::size_t encoder_size = encoder_instructions.size();
    std::size_t field_payload_size = field_block_payload.size();
    auto const encode_flags = static_cast<lsqpack_enc_flags>(
        LQEF_NO_INDEX | LQEF_NO_DYN);
    ASSERT_EQ(LQES_OK, lsqpack_enc_encode(
        &encoder, encoder_instructions.data(), &encoder_size,
        field_block_payload.data(), &field_payload_size, &field,
        encode_flags));

    std::array<unsigned char, 32> prefix {};
    lsqpack_enc_header_flags flags {};
    auto const prefix_size = lsqpack_enc_end_header(
        &encoder, prefix.data(), prefix.size(), &flags);
    ASSERT_GT(prefix_size, 0);
    lsqpack_enc_cleanup(&encoder);

    auto const field_section_size = static_cast<std::size_t>(prefix_size)
                                  + field_payload_size;
    ASSERT_LT(field_section_size, 64U);
    std::vector<unsigned char> request {
        0x01, static_cast<unsigned char>(field_section_size)};
    request.insert(request.end(), prefix.begin(), prefix.begin() + prefix_size);
    request.insert(request.end(), field_block_payload.begin(),
                   field_block_payload.begin() + field_payload_size);

    sx::quic::h3_capture_decoder decoder;
    auto records = decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size());

    ASSERT_EQ(1U, records.size());
    ASSERT_EQ(1U, records[0].fields.size());
    EXPECT_EQ(":authority", records[0].fields[0].name);
    EXPECT_EQ("origin.runner.lab", records[0].fields[0].value);
}

TEST(H3Capture, UnblocksHeadersFromQpackEncoderStream) {
    lsqpack_enc encoder {};
    std::array<unsigned char, LSQPACK_LONGEST_SDTC> capacity_instruction {};
    std::size_t capacity_size = capacity_instruction.size();
    ASSERT_EQ(0, lsqpack_enc_init(
        &encoder, nullptr, 4096, 4096, 16, LSQPACK_ENC_OPT_IX_AGGR,
        capacity_instruction.data(), &capacity_size));
    ASSERT_EQ(0, lsqpack_enc_start_header(&encoder, 0, 0));

    std::string const field_storage = "x-demodynamic-value";
    lsxpack_header field {};
    lsxpack_header_set_offset2(
        &field, field_storage.data(), 0, 6, 6, 13);
    std::array<unsigned char, 256> encoder_instructions {};
    std::array<unsigned char, 256> field_block_payload {};
    std::size_t encoder_size = encoder_instructions.size();
    std::size_t field_payload_size = field_block_payload.size();
    ASSERT_EQ(LQES_OK, lsqpack_enc_encode(
        &encoder, encoder_instructions.data(), &encoder_size,
        field_block_payload.data(), &field_payload_size, &field,
        static_cast<lsqpack_enc_flags>(0)));

    std::array<unsigned char, 32> prefix {};
    lsqpack_enc_header_flags flags {};
    auto const prefix_size = lsqpack_enc_end_header(
        &encoder, prefix.data(), prefix.size(), &flags);
    ASSERT_GT(prefix_size, 0);
    ASSERT_NE(0, flags & LSQECH_REF_NEW_ENTRIES);

    std::vector<unsigned char> request {0x01};
    auto const field_section_size = static_cast<std::size_t>(prefix_size)
                                  + field_payload_size;
    ASSERT_LT(field_section_size, 64U);
    request.push_back(static_cast<unsigned char>(field_section_size));
    request.insert(request.end(), prefix.begin(), prefix.begin() + prefix_size);
    request.insert(request.end(), field_block_payload.begin(),
                   field_block_payload.begin() + field_payload_size);

    sx::quic::h3_capture_decoder decoder;
    EXPECT_TRUE(decoder.ingest(
        socle::side_t::LEFT, 0, request.data(), request.size()).empty());

    std::vector<unsigned char> encoder_stream {0x02};
    encoder_stream.insert(encoder_stream.end(), capacity_instruction.begin(),
                          capacity_instruction.begin() + capacity_size);
    encoder_stream.insert(encoder_stream.end(), encoder_instructions.begin(),
                          encoder_instructions.begin() + encoder_size);
    auto records = decoder.ingest(
        socle::side_t::LEFT, 2, encoder_stream.data(), encoder_stream.size());
    lsqpack_enc_cleanup(&encoder);

    ASSERT_EQ(1U, records.size());
    ASSERT_EQ(1U, records[0].fields.size());
    EXPECT_EQ("x-demo", records[0].fields[0].name);
    EXPECT_EQ("dynamic-value", records[0].fields[0].value);
}
