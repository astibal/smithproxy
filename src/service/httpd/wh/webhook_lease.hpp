#pragma once

#include <openssl/crypto.h>

#include <algorithm>
#include <cstddef>
#include <ctime>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace sx::webserver {

class WebhookOverrideLease {
public:
    enum class Outcome { acquired, renewed, released, absent, conflict, invalid };

    struct Result {
        Outcome outcome{Outcome::invalid};
        std::string lease_id;
        std::time_t expires_at{};
    };

    struct ActiveTarget {
        bool active{};
        std::string url;
        bool tls_verify{true};
        std::time_t expires_at{};
    };

    Result acquire_or_renew(std::string url, const bool tls_verify,
                            const unsigned requested_ttl, std::string presented_id,
                            std::string generated_id, const std::time_t now) {
        if (url.empty() || requested_ttl == 0) return {};

        auto lock = std::scoped_lock(mutex_);
        if (active_unlocked(now)) {
            if (presented_id.empty() || !constant_time_equal(presented_id, lease_id_)) {
                return {Outcome::conflict, {}, expires_at_};
            }
            url_ = std::move(url);
            tls_verify_ = tls_verify;
            expires_at_ = now + static_cast<std::time_t>(clamp_ttl(requested_ttl));
            return {Outcome::renewed, lease_id_, expires_at_};
        }

        if (generated_id.empty()) return {};
        url_ = std::move(url);
        tls_verify_ = tls_verify;
        lease_id_ = std::move(generated_id);
        expires_at_ = now + static_cast<std::time_t>(clamp_ttl(requested_ttl));
        return {Outcome::acquired, lease_id_, expires_at_};
    }

    Result release(const std::string_view presented_id, const std::time_t now) {
        auto lock = std::scoped_lock(mutex_);
        if (!active_unlocked(now)) {
            clear_unlocked();
            return {Outcome::absent, {}, now};
        }
        if (presented_id.empty() || !constant_time_equal(presented_id, lease_id_)) {
            return {Outcome::conflict, {}, expires_at_};
        }
        clear_unlocked();
        return {Outcome::released, {}, now};
    }

    [[nodiscard]] ActiveTarget target(const std::time_t now) const {
        auto lock = std::scoped_lock(mutex_);
        if (!active_unlocked(now)) return {};
        return {true, url_, tls_verify_, expires_at_};
    }

private:
    static constexpr unsigned minimum_ttl = 10;
    static constexpr unsigned maximum_ttl = 300;

    static unsigned clamp_ttl(const unsigned ttl) {
        return std::clamp(ttl, minimum_ttl, maximum_ttl);
    }

    static bool constant_time_equal(const std::string_view lhs, const std::string_view rhs) {
        if (lhs.empty() || lhs.size() != rhs.size()) return false;
        return CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
    }

    [[nodiscard]] bool active_unlocked(const std::time_t now) const {
        return !lease_id_.empty() && !url_.empty() && expires_at_ > now;
    }

    void clear_unlocked() {
        url_.clear();
        lease_id_.clear();
        tls_verify_ = true;
        expires_at_ = 0;
    }

    mutable std::mutex mutex_;
    std::string url_;
    std::string lease_id_;
    bool tls_verify_{true};
    std::time_t expires_at_{};
};

} // namespace sx::webserver
