#ifndef MITMPROXY_UTILS_HPP
#define MITMPROXY_UTILS_HPP

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

inline replacement_route classify_replacement_route(std::string_view request_target,
                                                      std::string_view expected_target) {
    static constexpr std::string_view warning = "/SM/IT/HP/RO/XY/warning";
    static constexpr std::string_view override_prefix =
        "/SM/IT/HP/RO/XY/override/target=";

    if(request_target == warning ||
       (request_target.size() > warning.size() &&
        request_target.substr(0, warning.size()) == warning &&
        request_target[warning.size()] == '?')) {
        return replacement_route::warning;
    }

    if(expected_target.empty() || request_target.size() <= override_prefix.size() ||
       request_target.substr(0, override_prefix.size()) != override_prefix) {
        return replacement_route::none;
    }

    auto const value = request_target.substr(override_prefix.size());
    auto const separator = value.find_first_of("&?");
    auto const supplied_target = value.substr(0, separator);
    return supplied_target == expected_target
           ? replacement_route::override_action
           : replacement_route::none;
}

inline std::optional<std::string_view> replacement_parameter(
        std::string_view request_target, std::string_view name) {
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
        if(entries_.size() >= capacity_ && entries_.find(key) == entries_.end()) {
            entries_.erase(entries_.begin());
        }
        entries_[std::move(key)] = {
            std::move(token), now + static_cast<std::time_t>(lifetime_seconds)};
    }

    bool consume(std::string const& key,
                 std::optional<std::string_view> supplied,
                 std::time_t now) {
        std::scoped_lock lock(mutex_);
        auto const found = entries_.find(key);
        if(found == entries_.end()) return false;
        if(found->second.expires_at <= now) {
            entries_.erase(found);
            return false;
        }
        if(!override_token_matches(found->second.token, supplied)) return false;
        entries_.erase(found);
        return true;
    }

private:
    struct entry {
        std::string token;
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
        if(value < 0x20 || value == 0x7f || value == '\\') return std::nullopt;
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

} // namespace sx::mitmproxy

#endif // MITMPROXY_UTILS_HPP
