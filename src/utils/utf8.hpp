#pragma once

#include <cstddef>
#include <string_view>

namespace sx::text {

// Unicode permits control characters. Plain text permits only TAB, LF and CR
// among C0/C1 controls; both policies accept a UTF-8 BOM and empty input.
enum class utf8_policy { unicode, plain_text };

// Validate Unicode scalar encodings in one pass, without allocation or locale
// dependencies. Reject overlong sequences, isolated/truncated continuations,
// surrogate code points and values above U+10FFFF.
inline bool valid_utf8(std::string_view data, utf8_policy policy = utf8_policy::unicode) noexcept {
    for(std::size_t offset = 0; offset < data.size();) {
        const auto lead = static_cast<unsigned char>(data[offset++]);
        unsigned codepoint = lead;
        unsigned continuation = 0;
        unsigned minimum = 0;
        if(lead >= 0xc2 && lead <= 0xdf) {
            codepoint = lead & 0x1f;
            continuation = 1;
            minimum = 0x80;
        } else if(lead >= 0xe0 && lead <= 0xef) {
            codepoint = lead & 0x0f;
            continuation = 2;
            minimum = 0x800;
        } else if(lead >= 0xf0 && lead <= 0xf4) {
            codepoint = lead & 0x07;
            continuation = 3;
            minimum = 0x10000;
        } else if(lead >= 0x80) {
            return false;
        }
        if(continuation > data.size() - offset) {
            return false;
        }
        for(unsigned i = 0; i < continuation; ++i) {
            const auto byte = static_cast<unsigned char>(data[offset++]);
            if((byte & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (byte & 0x3f);
        }
        const bool surrogate = codepoint >= 0xd800 && codepoint <= 0xdfff;
        const bool invalid_scalar = codepoint < minimum || codepoint > 0x10ffff || surrogate;
        const bool whitespace = codepoint == '\t' || codepoint == '\n' || codepoint == '\r';
        const bool control = codepoint < 0x20 || (codepoint >= 0x7f && codepoint <= 0x9f);
        const bool forbidden_control = policy == utf8_policy::plain_text && control && !whitespace;
        if(invalid_scalar || forbidden_control) {
            return false;
        }
    }
    return true;
}

} // namespace sx::text
