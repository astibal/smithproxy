#ifndef MITMPROXY_UTILS_HPP
#define MITMPROXY_UTILS_HPP

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <mutex>
#include <unordered_map>

namespace sx::mitmproxy {

enum class hello_capture_action {
    retry,
    parse,
    disable
};

enum class client_certificate_action {
    none,
    block,
    whitelist_next
};

enum class replacement_route {
    none,
    warning,
    override_action
};

inline std::string_view replacement_request_target(std::string_view request) {
    if(request.empty() || request.front() == '/') return request;
    auto const first_space = request.find(' ');
    if(first_space == std::string_view::npos || first_space == 0) return {};
    auto const begin = first_space + 1;
    auto const end = request.find(' ', begin);
    if(end == std::string_view::npos || end == begin) return {};
    auto const version = request.substr(end + 1);
    if(version.substr(0, 5) != "HTTP/") return {};
    return request.substr(begin, end - begin);
}

inline std::optional<std::string_view> override_token_from_route(
        std::string_view request_target) {
    request_target = replacement_request_target(request_target);
    static constexpr std::string_view prefix = "/SM/IT/HP/RO/XY/override/";
    if(request_target.size() != prefix.size() + 32 ||
       request_target.substr(0, prefix.size()) != prefix) {
        return std::nullopt;
    }
    auto const token = request_target.substr(prefix.size());
    if(!std::all_of(token.begin(), token.end(), [](unsigned char ch) {
           return std::isxdigit(ch) != 0;
       })) {
        return std::nullopt;
    }
    return token;
}

inline std::optional<unsigned> override_ttl_seconds(int configured_seconds) {
    if(configured_seconds <= 0) return std::nullopt;
    return static_cast<unsigned>(configured_seconds);
}

inline std::string override_scope_key(std::string_view l4_key,
                                      std::string_view client_sni) {
    std::string normalized_sni(client_sni);
    std::transform(normalized_sni.begin(), normalized_sni.end(),
                   normalized_sni.begin(), [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    if(!normalized_sni.empty() && normalized_sni.back() == '.') {
        normalized_sni.pop_back();
    }

    return "override|" + std::to_string(l4_key.size()) + ":" +
           std::string(l4_key) + "|" + std::to_string(normalized_sni.size()) +
           ":" + normalized_sni;
}

inline replacement_route classify_replacement_route(std::string_view request_target) {
    request_target = replacement_request_target(request_target);
    static constexpr std::string_view warning = "/SM/IT/HP/RO/XY/warning";

    if(request_target == warning ||
       (request_target.size() > warning.size() &&
        request_target.substr(0, warning.size()) == warning &&
        request_target[warning.size()] == '?')) {
        return replacement_route::warning;
    }

    if(override_token_from_route(request_target)) {
        return replacement_route::override_action;
    }
    return replacement_route::none;
}

inline std::optional<std::string_view> replacement_parameter(
        std::string_view request_target, std::string_view name) {
    request_target = replacement_request_target(request_target);
    if(name.empty()) return std::nullopt;

    std::size_t begin = 0;
    while(begin < request_target.size()) {
        auto const separator = request_target.find_first_of("?&", begin);
        if(separator == std::string_view::npos) return std::nullopt;
        begin = separator + 1;
        auto const end = request_target.find_first_of("?&", begin);
        auto const item = request_target.substr(
            begin, end == std::string_view::npos ? std::string_view::npos : end - begin);
        if(item.size() > name.size() && item.substr(0, name.size()) == name &&
           item[name.size()] == '=') {
            return item.substr(name.size() + 1);
        }
        if(end == std::string_view::npos) return std::nullopt;
        begin = end;
    }
    return std::nullopt;
}

inline std::optional<std::string_view> query_parameter(
        std::string_view query, std::string_view name) {
    if(name.empty()) return std::nullopt;
    std::size_t begin = 0;
    while(begin <= query.size()) {
        auto const end = query.find('&', begin);
        auto const item = query.substr(
            begin, end == std::string_view::npos ? std::string_view::npos : end - begin);
        if(item.size() > name.size() && item.substr(0, name.size()) == name &&
           item[name.size()] == '=') {
            return item.substr(name.size() + 1);
        }
        if(end == std::string_view::npos) return std::nullopt;
        begin = end + 1;
    }
    return std::nullopt;
}

inline bool override_token_matches(
        std::string_view expected,
        std::optional<std::string_view> supplied) {
    if(expected.size() != 32 || !supplied || supplied->size() != expected.size()) {
        return false;
    }

    unsigned char difference = 0;
    for(std::size_t i = 0; i < expected.size(); ++i) {
        difference |= static_cast<unsigned char>(expected[i]) ^
                      static_cast<unsigned char>((*supplied)[i]);
    }
    return difference == 0;
}

class override_challenge_store {
public:
    explicit override_challenge_store(std::size_t capacity = 500)
        : capacity_(capacity) {}

    void issue(std::string key, std::string token, std::time_t now,
               unsigned lifetime_seconds) {
        std::scoped_lock lock(mutex_);
        remove_expired(now);
        if(entries_.size() >= capacity_ && entries_.find(token) == entries_.end()) {
            entries_.erase(entries_.begin());
        }
        entries_[token] = {
            std::move(key), now + static_cast<std::time_t>(lifetime_seconds)};
    }

    bool consume(std::string const& key,
                 std::optional<std::string_view> supplied,
                 std::time_t now) {
        std::scoped_lock lock(mutex_);
        if(!supplied || supplied->size() != 32) return false;
        auto const found = entries_.find(std::string(*supplied));
        if(found == entries_.end()) return false;
        if(found->second.expires_at <= now) {
            entries_.erase(found);
            return false;
        }
        if(found->second.scope != key) return false;
        entries_.erase(found);
        return true;
    }

private:
    struct entry {
        std::string scope;
        std::time_t expires_at;
    };

    void remove_expired(std::time_t now) {
        for(auto it = entries_.begin(); it != entries_.end();) {
            if(it->second.expires_at <= now) it = entries_.erase(it);
            else ++it;
        }
    }

    std::size_t capacity_;
    std::mutex mutex_;
    std::unordered_map<std::string, entry> entries_;
};

inline client_certificate_action client_certificate_next(bool requested,
                                                          int configured_action) {
    if(!requested) return client_certificate_action::none;
    if(configured_action == 0) return client_certificate_action::block;
    if(configured_action == 2) return client_certificate_action::whitelist_next;
    return client_certificate_action::none;
}

inline bool tls_verification_failed(unsigned status,
                                    unsigned ok_flag,
                                    unsigned client_certificate_flag) {
    status &= ~client_certificate_flag;
    return status != 0 && status != ok_flag;
}

inline hello_capture_action hello_capture_next(bool tls_transport,
                                               std::size_t buffer_size,
                                               std::size_t record_header_size,
                                               std::size_t attempt,
                                               std::size_t max_attempts) {
    if(!tls_transport || max_attempts == 0) return hello_capture_action::disable;
    if(buffer_size > record_header_size) return hello_capture_action::parse;
    return attempt < max_attempts
           ? hello_capture_action::retry
           : hello_capture_action::disable;
}

inline bool half_close_grace_expired(std::time_t started_at,
                                     long timeout_seconds,
                                     std::time_t now) {
    if(started_at <= 0) return false;
    if(timeout_seconds <= 0) return true;
    if(now < started_at) return false;
    return std::difftime(now, started_at) >= timeout_seconds;
}

inline std::string html_escape(std::string_view input) {
    std::string output;
    output.reserve(input.size());
    for(char ch: input) {
        switch(ch) {
            case '&': output += "&amp;"; break;
            case '<': output += "&lt;"; break;
            case '>': output += "&gt;"; break;
            case '"': output += "&quot;"; break;
            case '\'': output += "&#39;"; break;
            default: output.push_back(ch); break;
        }
    }
    return output;
}

inline std::string query_encode(std::string_view input) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.size());
    for(unsigned char ch: input) {
        bool const unreserved = (ch >= 'a' && ch <= 'z') ||
                                (ch >= 'A' && ch <= 'Z') ||
                                (ch >= '0' && ch <= '9') ||
                                ch == '-' || ch == '.' || ch == '_' || ch == '~';
        if(unreserved) {
            output.push_back(static_cast<char>(ch));
        } else {
            output.push_back('%');
            output.push_back(hex[ch >> 4]);
            output.push_back(hex[ch & 0x0f]);
        }
    }
    return output;
}

inline std::optional<std::string> decode_relative_target(std::string_view input) {
    auto hex_value = [](char ch) -> int {
        if(ch >= '0' && ch <= '9') return ch - '0';
        if(ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if(ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };

    std::string output;
    output.reserve(input.size());
    for(std::size_t i = 0; i < input.size(); ++i) {
        unsigned char value = static_cast<unsigned char>(input[i]);
        if(value == '%') {
            if(i + 2 >= input.size()) return std::nullopt;
            auto const high = hex_value(input[i + 1]);
            auto const low = hex_value(input[i + 2]);
            if(high < 0 || low < 0) return std::nullopt;
            value = static_cast<unsigned char>((high << 4) | low);
            i += 2;
        }
        if(value < 0x20 || value == 0x7f || value == '\\' ||
           value == ';' || value == ',') {
            return std::nullopt;
        }
        output.push_back(static_cast<char>(value));
    }

    if(output.empty() || output.front() != '/' ||
       (output.size() > 1 && output[1] == '/')) {
        return std::nullopt;
    }
    return output;
}

inline std::optional<std::string> first_alpn_protocol(std::string_view wire_list) {
    if(wire_list.empty()) return std::nullopt;
    auto const length = static_cast<unsigned char>(wire_list.front());
    if(length == 0 || length > wire_list.size() - 1) return std::nullopt;
    return std::string(wire_list.substr(1, length));
}

// A peer object can outlive its underlying descriptor while both sides of a
// stream are closing.  Validate through the transport so virtual descriptors
// remain supported instead of relying on a numeric fd convention.
template<class Host>
bool half_close_peer_can_drain(Host* cx) {
    if(cx == nullptr) return false;

    auto* peer = cx->peer();
    if(peer == nullptr || peer->com() == nullptr || peer->writebuf() == nullptr) {
        return false;
    }

    return peer->com()->descriptor_valid(peer->socket()) &&
           !peer->writebuf()->empty();
}

// Once an upstream EOF has been observed, the downstream side only needs to
// stay alive while application or transport output is still queued.
template<class Host>
bool half_close_peer_drained(Host* cx) {
    if(cx == nullptr) return false;

    auto* peer = cx->peer();
    if(peer == nullptr || peer->com() == nullptr || peer->writebuf() == nullptr) {
        return false;
    }

    return peer->com()->descriptor_valid(peer->socket()) &&
           peer->writebuf()->empty() &&
           !peer->com()->write_event_pending();
}

} // namespace sx::mitmproxy

#endif // MITMPROXY_UTILS_HPP
