#pragma once

#include <service/admin/admin_config.hpp>
#include <utils/crypto.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

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

    // Exclusively reserves one capability while its administrator record is
    // persisted. Destruction releases an uncommitted reservation for a safe retry.
    class TokenReservation {
    public:
        TokenReservation(const TokenReservation&) = delete;
        TokenReservation& operator=(const TokenReservation&) = delete;

        TokenReservation(TokenReservation&& other) noexcept
            : store_(std::exchange(other.store_, nullptr)),
              verifier_(std::move(other.verifier_)),
              reservation_id_(std::exchange(other.reservation_id_, 0)),
              administrator_(std::move(other.administrator_)) {}

        TokenReservation& operator=(TokenReservation&& other) noexcept {
            if(this == &other) return *this;
            release();
            store_ = std::exchange(other.store_, nullptr);
            verifier_ = std::move(other.verifier_);
            reservation_id_ = std::exchange(other.reservation_id_, 0);
            administrator_ = std::move(other.administrator_);
            return *this;
        }

        ~TokenReservation() { release(); }

        [[nodiscard]] const std::string& administrator() const noexcept {
            return administrator_;
        }

        // Permanently consumes the reserved capability after durable success.
        [[nodiscard]] bool commit() {
            if(!store_) return false;
            const bool consumed = store_->finish_reservation(
                verifier_, reservation_id_, true);
            store_ = nullptr;
            reservation_id_ = 0;
            return consumed;
        }

    private:
        friend class AdminEnrollmentStore;

        TokenReservation(AdminEnrollmentStore& store, std::string verifier,
                         std::uint64_t reservation_id, std::string administrator)
            : store_(&store), verifier_(std::move(verifier)),
              reservation_id_(reservation_id),
              administrator_(std::move(administrator)) {}

        void release() noexcept {
            if(store_) {
                store_->finish_reservation(verifier_, reservation_id_, false);
            }
            store_ = nullptr;
            reservation_id_ = 0;
        }

        AdminEnrollmentStore* store_ {nullptr};
        std::string verifier_;
        std::uint64_t reservation_id_ {0};
        std::string administrator_;
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

    // Exclusively reserves a capability so persistence can fail without losing
    // it and parallel callers still cannot reuse it.
    std::optional<TokenReservation> reserve(
        std::string_view token,
        std::int64_t now = unix_seconds()) {
        const bool valid_length = token.size() == 64U;
        const bool valid_characters = valid_length &&
            std::all_of(token.begin(), token.end(), [](const unsigned char byte) {
                const bool decimal = byte >= '0' && byte <= '9';
                const bool lowercase_hex = byte >= 'a' && byte <= 'f';
                return decimal || lowercase_hex;
            });
        if(!valid_characters) return std::nullopt;

        auto verifier = sx::crypto::sha256(token);
        if(!verifier) return std::nullopt;

        auto guard = std::scoped_lock(lock_);
        const auto found = entries_.find(*verifier);
        if(found == entries_.end()) return std::nullopt;
        if(found->second.expires_at_unix_seconds <= now) {
            entries_.erase(found);
            return std::nullopt;
        }
        if(found->second.reservation_id != 0) return std::nullopt;

        const auto reservation_id = next_reservation_id_locked();
        found->second.reservation_id = reservation_id;
        return TokenReservation(
            *this, *verifier, reservation_id, found->second.administrator);
    }

    // Compatibility helper for transports that complete no persistent work.
    std::optional<std::string> consume(
        std::string_view token,
        std::int64_t now = unix_seconds()) {
        auto reservation = reserve(token, now);
        if(!reservation) return std::nullopt;
        auto administrator = reservation->administrator();
        if(!reservation->commit()) return std::nullopt;
        return administrator;
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
        std::uint64_t reservation_id {0};
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

    std::uint64_t next_reservation_id_locked() noexcept {
        ++last_reservation_id_;
        if(last_reservation_id_ == 0) ++last_reservation_id_;
        return last_reservation_id_;
    }

    // Completes a reservation owned by reservation_id. A committed reservation
    // consumes the token; an uncommitted one becomes available for safe retry.
    bool finish_reservation(
        const std::string& verifier,
        std::uint64_t reservation_id,
        bool consume) noexcept {
        auto guard = std::scoped_lock(lock_);
        const auto found = entries_.find(verifier);
        const bool owns_reservation = found != entries_.end() &&
            found->second.reservation_id == reservation_id;
        if(!owns_reservation) return false;
        if(consume)
            entries_.erase(found);
        else
            found->second.reservation_id = 0;
        return true;
    }

    std::mutex lock_;
    std::map<std::string, Entry> entries_;
    std::uint64_t last_reservation_id_ {0};
};

}  // namespace sx::webserver
