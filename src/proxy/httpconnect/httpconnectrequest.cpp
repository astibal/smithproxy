#include <proxy/httpconnect/httpconnectrequest.hpp>

#include <charconv>

namespace {

std::optional<unsigned short> parse_port(std::string_view text) {
    unsigned int port = 0;
    auto const result = std::from_chars(text.data(), text.data() + text.size(), port);
    if(result.ec != std::errc{} or result.ptr != text.data() + text.size()
       or port == 0 or port > 65535) {
        return std::nullopt;
    }
    return static_cast<unsigned short>(port);
}

} // namespace

std::optional<HttpConnectRequest> HttpConnectRequest::parse(std::string_view line) {
    if(line.size() >= 2 and line.substr(line.size() - 2) == "\r\n") {
        line.remove_suffix(2);
    }

    auto const method_end = line.find(' ');
    auto const authority_end = line.find(' ', method_end + 1);
    if(method_end == std::string_view::npos or authority_end == std::string_view::npos
       or line.substr(0, method_end) != "CONNECT") {
        return std::nullopt;
    }

    auto const authority = line.substr(method_end + 1, authority_end - method_end - 1);
    auto const version = line.substr(authority_end + 1);
    if((version != "HTTP/1.0" and version != "HTTP/1.1") or authority.empty()) {
        return std::nullopt;
    }

    std::string_view host;
    std::string_view port_text;
    if(authority.front() == '[') {
        auto const bracket = authority.find(']');
        if(bracket == std::string_view::npos or bracket + 1 >= authority.size()
           or authority[bracket + 1] != ':') {
            return std::nullopt;
        }
        host = authority.substr(1, bracket - 1);
        port_text = authority.substr(bracket + 2);
    } else {
        auto const colon = authority.rfind(':');
        if(colon == std::string_view::npos or authority.find(':') != colon) {
            return std::nullopt;
        }
        host = authority.substr(0, colon);
        port_text = authority.substr(colon + 1);
    }

    auto const port = parse_port(port_text);
    if(host.empty() or not port) {
        return std::nullopt;
    }

    return HttpConnectRequest {std::string(host), *port};
}
