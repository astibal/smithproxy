#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace sx::webserver {

// Bounds expensive password-verification work by both client source and
// administrator name. State is process-local, contains no credentials, and is
// deliberately capped so hostile identifiers cannot grow memory indefinitely.
class LoginThrottle {
public:
    struct Decision {
        bool allowed {false};
        std::int64_t retry_after_seconds {0};
    };

    static constexpr std::size_t principal_attempt_limit = 6;
    static constexpr std::size_t source_attempt_limit = 30;
    static constexpr std::int64_t window_seconds = 60;
    static constexpr std::size_t capacity = 1024;
    static constexpr std::size_t maximum_principal_key_bytes = 64;

    static LoginThrottle& instance() {
        static LoginThrottle throttle;
        return throttle;
    }

    Decision permit(
        std::string_view source,
        std::string_view principal,
        std::int64_t now = unix_seconds()) {
        const auto source_key = source.empty() ? std::string("<unknown>")
                                               : std::string(source);
        const auto principal_identifier = principal_key(principal);

        auto guard = std::scoped_lock(lock_);
        prune(source_attempts_, now);
        prune(principal_attempts_, now);
        auto& source_entry = entry(source_attempts_, source_key, now);
        auto& principal_entry = entry(principal_attempts_, principal_identifier, now);
        refresh(source_entry, now);
        refresh(principal_entry, now);

        const auto source_retry = retry_after(
            source_entry, source_attempt_limit, now);
        const auto principal_retry = retry_after(
            principal_entry, principal_attempt_limit, now);
        const auto retry = std::max(source_retry, principal_retry);
        if(retry > 0) return {false, retry};

        ++source_entry.attempts;
        ++principal_entry.attempts;
        return {true, 0};
    }

    // A successful login proves ownership of the principal and clears only
    // that name's typo/brute-force budget. The source budget remains a CPU
    // guard even when many valid accounts share one client address.
    void record_success(std::string_view principal) {
        auto guard = std::scoped_lock(lock_);
        principal_attempts_.erase(principal_key(principal));
    }

    void clear() {
        auto guard = std::scoped_lock(lock_);
        source_attempts_.clear();
        principal_attempts_.clear();
    }

    std::pair<std::size_t, std::size_t> entry_counts(
        std::int64_t now = unix_seconds()) {
        auto guard = std::scoped_lock(lock_);
        prune(source_attempts_, now);
        prune(principal_attempts_, now);
        return {source_attempts_.size(), principal_attempts_.size()};
    }

private:
    struct Entry {
        std::int64_t window_started {0};
        std::size_t attempts {0};
    };

    using Entries = std::unordered_map<std::string, Entry>;

    static std::int64_t unix_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string principal_key(std::string_view principal) {
        const bool valid = !principal.empty() &&
            principal.size() <= maximum_principal_key_bytes;
        return valid ? std::string(principal) : std::string("<invalid>");
    }

    static bool window_expired(const Entry& value, std::int64_t now) {
        const bool clock_moved_back = now < value.window_started;
        const bool elapsed = !clock_moved_back &&
            now - value.window_started >= window_seconds;
        return clock_moved_back || elapsed;
    }

    static void refresh(Entry& value, std::int64_t now) {
        if(window_expired(value, now)) value = Entry{now, 0};
    }

    static std::int64_t retry_after(
        const Entry& value, std::size_t limit, std::int64_t now) {
        if(value.attempts < limit) return 0;
        return std::max<std::int64_t>(1, value.window_started + window_seconds - now);
    }

    static void prune(Entries& values, std::int64_t now) {
        for(auto iterator = values.begin(); iterator != values.end();) {
            if(window_expired(iterator->second, now))
                iterator = values.erase(iterator);
            else
                ++iterator;
        }
    }

    static Entry& entry(Entries& values, const std::string& key, std::int64_t now) {
        const auto found = values.find(key);
        if(found != values.end()) return found->second;

        if(values.size() >= capacity) {
            const auto oldest = std::min_element(
                values.begin(), values.end(), [](const auto& left, const auto& right) {
                    return left.second.window_started < right.second.window_started;
                });
            values.erase(oldest);
        }
        return values.emplace(key, Entry{now, 0}).first->second;
    }

    std::mutex lock_;
    Entries source_attempts_;
    Entries principal_attempts_;
};

}  // namespace sx::webserver
