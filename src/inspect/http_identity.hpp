#pragma once

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>
#include <string>
#include <string_view>

namespace sx::inspect::http_detail {

inline bool is_unambiguous_authority(std::string_view value) noexcept {
    if(value.empty()) return false;
    if(std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch <= 0x20 || ch == 0x7f || ch == '/' ||
               ch == '?' || ch == '#' || ch == '@' || ch == '\\';
    })) {
        return false;
    }

    std::string_view host = value;
    std::string_view port;
    if(value.front() == '[') {
        const auto closing = value.find(']');
        if(closing == std::string_view::npos || closing == 1) return false;
        host = value.substr(1, closing - 1);
        const auto suffix = value.substr(closing + 1);
        if(!suffix.empty()) {
            if(suffix.front() != ':' || suffix.size() == 1) return false;
            port = suffix.substr(1);
        }
        in6_addr address{};
        const std::string host_copy(host);
        if(inet_pton(AF_INET6, host_copy.c_str(), &address) != 1) return false;
    } else {
        if(value.find('[') != std::string_view::npos ||
           value.find(']') != std::string_view::npos) {
            return false;
        }
        const auto colon = value.find(':');
        if(colon != std::string_view::npos) {
            if(value.find(':', colon + 1) != std::string_view::npos) return false;
            host = value.substr(0, colon);
            port = value.substr(colon + 1);
            if(port.empty()) return false;
        }
        if(host.empty()) return false;
    }

    if(!port.empty()) {
        unsigned int number = 0;
        const auto parsed = std::from_chars(
            port.data(), port.data() + port.size(), number);
        if(parsed.ec != std::errc{} || parsed.ptr != port.data() + port.size() ||
           number == 0 || number > 65535) {
            return false;
        }
    }
    return true;
}

inline bool is_valid_request_path(std::string_view method,
                                  std::string_view value) noexcept {
    if(value.empty()) return false;
    if(value == "*") return method == "OPTIONS";
    if(value.front() != '/') return false;
    return std::none_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch <= 0x20 || ch >= 0x7f || ch == '#';
    });
}

inline bool scheme_requires_authority(std::string_view value) noexcept {
    auto const equals = [&](std::string_view expected) {
        return value.size() == expected.size() &&
            std::equal(value.begin(), value.end(), expected.begin(),
                       [](unsigned char left, unsigned char right) {
                           if(left >= 'A' && left <= 'Z') left += 'a' - 'A';
                           return left == right;
                       });
    };
    return equals("http") || equals("https");
}

} // namespace sx::inspect::http_detail
