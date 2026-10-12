#pragma once

#include <charconv>
#include <optional>
#include <string_view>

namespace sx::ssh::detail {

inline std::optional<unsigned int> parse_port(std::string_view text) {
    unsigned int port = 0;
    auto const [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), port);
    if (error != std::errc{} || end != text.data() + text.size() ||
        port == 0 || port > 65535U) {
        return std::nullopt;
    }
    return port;
}

} // namespace sx::ssh::detail
