#ifndef SMITHPROXY_EXPLICITPROXYPORT_HPP
#define SMITHPROXY_EXPLICITPROXYPORT_HPP

#include <charconv>
#include <optional>
#include <string>
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

struct source_endpoint {
    std::string host;
    unsigned short port;
};

template <class Resolver>
std::optional<source_endpoint> resolve_source_endpoint(int socket,
                                                       Resolver&& resolver) {
    std::string host;
    std::string port_text;
    if(!resolver(socket, &host, &port_text)) return std::nullopt;
    const auto port = parse_source_port(port_text);
    if(!port) return std::nullopt;
    return source_endpoint {std::move(host), *port};
}

} // namespace sx::explicit_proxy

#endif // SMITHPROXY_EXPLICITPROXYPORT_HPP
