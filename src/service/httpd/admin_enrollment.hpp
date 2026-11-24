#pragma once

#include <service/admin/admin_config.hpp>
#include <utils/crypto.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace sx::webserver {

// Keeps short-lived administrator enrollment capabilities in process memory.
// Plaintext tokens are returned once to the issuer; only verifiers remain.
class AdminEnrollmentStore {
public:
    // Returns a capability once together with its absolute expiry time.
    struct IssuedToken {
        std::string token;
        std::int64_t expires_at_unix_seconds {0};
    };

    static constexpr std::int64_t default_ttl_seconds = 600;
    static constexpr std::size_t capacity = 16;

    // Shares one bounded capability store between every management transport.
    static AdminEnrollmentStore& instance() {
        static AdminEnrollmentStore store;
        return store;
    }

    // Restricts names to the portable administrator identifier grammar.
    static bool valid_administrator(std::string_view value) {
        return sx::admin::valid_name(value);
    }

    // Issues one short-lived capability without retaining its plaintext value.
    std::optional<IssuedToken> issue(
        std::string administrator,
        std::int64_t now = unix_seconds(),
        std::int64_t ttl_seconds = default_ttl_seconds) {
        const bool valid_name = valid_administrator(administrator);
        const bool valid_ttl = ttl_seconds > 0 && ttl_seconds <= default_ttl_seconds;
        const bool expiry_overflows = valid_ttl &&
            now > std::numeric_limits<std::int64_t>::max() - ttl_seconds;
        if(!valid_name || !valid_ttl || expiry_overflows) return std::nullopt;

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

    // Atomically consumes a capability so parallel callers cannot reuse it.
    std::optional<std::string> consume(
        std::string_view token,
        std::int64_t now = unix_seconds()) {
        const bool valid_length = token.size() == 64U;
        const bool valid_characters = valid_length &&
            std::all_of(token.begin(), token.end(), [](const unsigned char byte) {
                return std::isdigit(byte) || (byte >= 'a' && byte <= 'f');
            });
        if(!valid_characters) return std::nullopt;

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

    // Removes every outstanding capability, primarily for controlled shutdown
    // and isolated tests.
    void clear() {
        auto guard = std::scoped_lock(lock_);
        entries_.clear();
    }

    // Returns the live capability count after pruning expired entries.
    std::size_t size(std::int64_t now = unix_seconds()) {
        auto guard = std::scoped_lock(lock_);
        prune_locked(now);
        return entries_.size();
    }

private:
    // Associates one verifier with the administrator named by the issuer.
    struct Entry {
        std::string administrator;
        std::int64_t expires_at_unix_seconds {0};
    };

    // Produces wall-clock seconds used by externally visible expiry values.
    static std::int64_t unix_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // Removes expired entries while the caller holds lock_.
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
