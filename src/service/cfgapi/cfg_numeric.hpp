#pragma once

#include <charconv>
#include <optional>
#include <string_view>
#include <system_error>
#include <cstdint>

namespace sx::cfg {

template <class Number>
std::optional<Number> parse_number(std::string_view text) {
    if(text.empty()) return Number{};
    Number value {};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if(parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
        return std::nullopt;
    return value;
}

inline bool integer_array_path(std::string_view path) noexcept {
    constexpr std::string_view quick_ports = "settings.udp_quick_ports";
    constexpr std::string_view warning_ports = ".redirect_warning_ports";
    return path == quick_ports ||
           (path.size() >= warning_ports.size() &&
            path.substr(path.size() - warning_ports.size()) == warning_ports);
}

inline std::optional<std::uint16_t> parse_transport_port(
        std::string_view text, std::uint16_t required_headroom = 0) noexcept {
    if(text.empty()) return std::nullopt;
    auto const value = parse_number<unsigned int>(text);
    if(!value || *value > 65535U - required_headroom) return std::nullopt;
    return static_cast<std::uint16_t>(*value);
}

} // namespace sx::cfg
