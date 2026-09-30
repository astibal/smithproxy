#ifndef SMITHPROXY_EXPLICITPROXYPORT_HPP
#define SMITHPROXY_EXPLICITPROXYPORT_HPP

#include <charconv>
#include <optional>
#include <string_view>

namespace sx::explicit_proxy {

inline std::optional<unsigned short> parse_source_port(std::string_view text) {
    unsigned int port = 0;
    auto const result = std::from_chars(text.data(), text.data() + text.size(), port);
    if(result.ec != std::errc{} || result.ptr != text.data() + text.size()
       || port == 0 || port > 65535) {
        return std::nullopt;
    }
    return static_cast<unsigned short>(port);
}

} // namespace sx::explicit_proxy

#endif // SMITHPROXY_EXPLICITPROXYPORT_HPP
