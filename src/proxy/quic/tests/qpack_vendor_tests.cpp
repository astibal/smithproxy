#include <gtest/gtest.h>

#include <array>
#include <string>

#include <lsqpack.h>
#include <lsxpack_header.h>

namespace {

// Minimal callback state used to verify that the vendored decoder exposes
// decoded name/value fields in the form expected by the future H3 adapter.
struct HeaderContext {
    std::array<char, 128> storage{};
    lsxpack_header header{};
    std::string name;
    std::string value;
};

void header_unblocked(void*) {}

lsxpack_header* prepare_header(void* opaque, lsxpack_header*, size_t space) {
    auto* context = static_cast<HeaderContext*>(opaque);
    if (space > context->storage.size()) {
        return nullptr;
    }

    lsxpack_header_prepare_decode(
            &context->header, context->storage.data(), 0, space);
    return &context->header;
}

int process_header(void* opaque, lsxpack_header* header) {
    auto* context = static_cast<HeaderContext*>(opaque);
    context->name.assign(lsxpack_header_get_name(header), header->name_len);
    context->value.assign(lsxpack_header_get_value(header), header->val_len);
    return 0;
}

const lsqpack_dec_hset_if decoder_callbacks{
        header_unblocked,
        prepare_header,
        process_header,
};

}  // namespace

TEST(QpackVendor, DecodesStaticRequestPseudoHeader) {
    // Required Insert Count = 0, Delta Base = 0, followed by static-table
    // index 17 (:method = GET) from RFC 9204 Appendix A.
    const std::array<unsigned char, 3> field_section{0x00, 0x00, 0xD1};
    const unsigned char* cursor = field_section.data();
    std::array<unsigned char, LSQPACK_LONGEST_HEADER_ACK> decoder_output{};
    size_t decoder_output_size = decoder_output.size();
    HeaderContext context;
    lsqpack_dec decoder{};

    lsqpack_dec_init(&decoder, nullptr, 4096, 16, &decoder_callbacks,
                     static_cast<lsqpack_dec_opts>(0));
    const auto status = lsqpack_dec_header_in(
            &decoder, &context, 0, field_section.size(), &cursor,
            field_section.size(), decoder_output.data(), &decoder_output_size);
    lsqpack_dec_cleanup(&decoder);

    EXPECT_EQ(LQRHS_DONE, status);
    EXPECT_EQ(field_section.data() + field_section.size(), cursor);
    EXPECT_EQ(":method", context.name);
    EXPECT_EQ("GET", context.value);
}
