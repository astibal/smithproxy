#pragma once

#include <charconv>
#include <optional>
#include <string>
#include <string_view>

namespace sx::proxy {

// The callback supplies a complete HTTP/1 reply, never a chunked stream or
// bytes to be interpreted as another response. Check framing before publication.
inline bool valid_connect_reply(std::string_view reply) {

    const auto header_end = reply.find("\r\n\r\n");
    const auto line_end = reply.find("\r\n");

    // A complete, bounded header block must precede any response body.
    if(reply.size() > 256 * 1024 || header_end == std::string_view::npos ||
       header_end + 4 >= 8192 || line_end < 13)
        return false;

    // Accept only final HTTP/1 responses. The reason phrase must stay on
    // this status line, without control bytes or an injected second line.
    const auto line = reply.substr(0, line_end);
    if(line.substr(0, 9) != "HTTP/1.0 " && line.substr(0, 9) != "HTTP/1.1 ")
        return false;

    if(line[9] < '2' || line[9] > '5' || line[10] < '0' || line[10] > '9' ||
       line[11] < '0' || line[11] > '9' || line[12] != ' ')
        return false;

    for(unsigned char byte : line.substr(13)) {
        if(byte < 32 || byte == 127)
            return false;
    }

    // Header names are ASCII tokens. Normalize their case only after checking
    // each byte, so framing fields have one unambiguous interpretation.
    std::optional<std::size_t> content_length;
    auto cursor = line_end + 2;

    while(cursor < header_end) {
        const auto end = reply.find("\r\n", cursor);
        const auto header = reply.substr(cursor, end - cursor);
        const auto colon = header.find(':');

        if(colon == 0 || colon == std::string_view::npos)
            return false;

        std::string name;
        for(unsigned char byte : header.substr(0, colon)) {
            const bool alpha = (byte >= 'a' && byte <= 'z') ||
                               (byte >= 'A' && byte <= 'Z');
            const bool digit = byte >= '0' && byte <= '9';

            if(!alpha && !digit &&
               std::string_view("!#$%&'*+-.^_`|~").find(byte) == std::string_view::npos)
                return false;

            name += static_cast<char>(
                byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte);
        }

        auto value = header.substr(colon + 1);
        for(unsigned char byte : value) {
            if((byte < 32 && byte != '\t') || byte == 127)
                return false;
        }

        // The callback returns one complete reply, not a chunked stream.
        if(name == "transfer-encoding")
            return false;

        if(name == "content-length") {
            // Reject duplicate lengths, even when their values agree.
            if(content_length)
                return false;

            const auto first = value.find_first_not_of(" \t");
            if(first == std::string_view::npos)
                return false;

            value = value.substr(first, value.find_last_not_of(" \t") - first + 1);
            std::size_t length = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), length);

            if(parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
                return false;

            content_length = length;
        }

        cursor = end + 2;
    }

    // No undeclared or leftover bytes may become the next tunnel message.
    const auto body_size = reply.size() - header_end - 4;
    return content_length ? *content_length == body_size : body_size == 0;
}

} // namespace sx::proxy
