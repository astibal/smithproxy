#include "proxy/quic/wire.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>

namespace quic = sx::quic;

namespace {

[[noreturn]] void invariant_failed() {
    __builtin_trap();
}

void check_header(quic::parse_result const& parsed, std::size_t input_size) {
    if (!parsed) {
        if (parsed.error_offset > input_size) invariant_failed();
        return;
    }
    auto const& value = parsed.value;
    if (value.packet_number_offset > input_size || value.packet_end > input_size) {
        invariant_failed();
    }
    if (value.destination_connection_id.size() > 20
        || value.source_connection_id.size() > 20) {
        invariant_failed();
    }
    if (value.form == quic::packet_form::short_header) {
        if (value.packet_number_offset != 1 || value.packet_end != input_size) {
            invariant_failed();
        }
    }
    if (value.protected_payload_length) {
        if (*value.protected_payload_length
            > std::numeric_limits<std::size_t>::max() - value.packet_number_offset) {
            invariant_failed();
        }
        if (value.packet_end
            != value.packet_number_offset
                + static_cast<std::size_t>(*value.protected_payload_length)) {
            invariant_failed();
        }
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    auto const parsed = quic::parse_header(data, size);
    check_header(parsed, size);

    // Parsing is deterministic and must not retain pointers into prior calls.
    auto const repeated = quic::parse_header(data, size);
    if (parsed.error != repeated.error
        || parsed.error_offset != repeated.error_offset
        || parsed.value.packet_end != repeated.value.packet_end) {
        invariant_failed();
    }

    auto const varint = quic::parse_varint(data, size);
    if (varint) {
        if (varint.encoded_size > size
            || (varint.encoded_size != 1 && varint.encoded_size != 2
                && varint.encoded_size != 4 && varint.encoded_size != 8)) {
            invariant_failed();
        }
    }

    // Exercise explicit null-input contracts independently of fuzzer storage.
    if (size != 0 && (data[0] & 1U) != 0) {
        auto const null_header = quic::parse_header(nullptr, size);
        auto const null_varint = quic::parse_varint(nullptr, size);
        if (null_header.error != quic::parse_error::empty
            || null_varint.error != quic::parse_error::truncated) {
            invariant_failed();
        }
    }
    return 0;
}
