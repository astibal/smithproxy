#pragma once

#include <utils/crypto.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <map>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace sx::webserver {

// Keeps short-lived GUI enrollment capabilities in process memory. Plaintext
// tokens are returned once to the privileged CLI; only their verifier remains.
class GuiEnrollmentStore {
public:
    struct IssuedToken {
        std::string token;
        std::int64_t expires_at_unix_seconds {0};
    };

    static constexpr std::int64_t default_ttl_seconds = 600;
    static constexpr std::size_t capacity = 16;

    static GuiEnrollmentStore& instance() {
        static GuiEnrollmentStore store;
        return store;
    }

    static bool valid_administrator(std::string_view value) {
        return !value.empty() && value.size() <= 64U &&
               std::all_of(value.begin(), value.end(), [](const unsigned char byte) {
                   return std::isalnum(byte) || byte == '.' || byte == '_' ||
                          byte == '-' || byte == '@';
               });
    }

    std::optional<IssuedToken> issue(
        std::string administrator,
        std::int64_t now = unix_seconds(),
        std::int64_t ttl_seconds = default_ttl_seconds) {
        if(!valid_administrator(administrator) || ttl_seconds <= 0 ||
           ttl_seconds > default_ttl_seconds ||
           now > std::numeric_limits<std::int64_t>::max() - ttl_seconds)
            return std::nullopt;
        auto token = sx::crypto::random_hex(32);
        if(!token) return std::nullopt;
        auto verifier = sx::crypto::sha256(*token);
        if(!verifier) return std::nullopt;

        const auto expires_at = now + ttl_seconds;
        auto guard = std::scoped_lock(lock_);
        prune_locked(now);
        if(entries_.size() >= capacity) return std::nullopt;
        const auto inserted = entries_.emplace(
            std::move(*verifier), Entry{std::move(administrator), expires_at}).second;
        if(!inserted) return std::nullopt;
        return IssuedToken{std::move(*token), expires_at};
    }

    // Atomically removes a valid capability. Parallel consumers can never
    // receive the same administrator grant more than once.
    std::optional<std::string> consume(
        std::string_view token,
        std::int64_t now = unix_seconds()) {
        if(token.size() != 64U ||
           !std::all_of(token.begin(), token.end(), [](const unsigned char byte) {
               return std::isdigit(byte) || (byte >= 'a' && byte <= 'f');
           })) return std::nullopt;
        auto verifier = sx::crypto::sha256(token);
        if(!verifier) return std::nullopt;

        auto guard = std::scoped_lock(lock_);
        const auto found = entries_.find(*verifier);
        if(found == entries_.end()) return std::nullopt;
        auto entry = std::move(found->second);
        entries_.erase(found);
        if(entry.expires_at_unix_seconds <= now) return std::nullopt;
        return entry.administrator;
    }

    void clear() {
        auto guard = std::scoped_lock(lock_);
        entries_.clear();
    }

    std::size_t size(std::int64_t now = unix_seconds()) {
        auto guard = std::scoped_lock(lock_);
        prune_locked(now);
        return entries_.size();
    }

private:
    struct Entry {
        std::string administrator;
        std::int64_t expires_at_unix_seconds {0};
    };

    static std::int64_t unix_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void prune_locked(std::int64_t now) {
        for(auto iterator = entries_.begin(); iterator != entries_.end();) {
            if(iterator->second.expires_at_unix_seconds <= now)
                iterator = entries_.erase(iterator);
            else
                ++iterator;
        }
    }

    std::mutex lock_;
    std::map<std::string, Entry> entries_;
};

}  // namespace sx::webserver
