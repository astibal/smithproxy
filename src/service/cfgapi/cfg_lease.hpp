#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace sx::cfg {

// Short-lived exclusive permission to validate and commit a change against
// one running-config revision. Expiration prevents abandoned clients from
// blocking writers indefinitely.
class CfgLease {
public:
    using Clock = std::chrono::steady_clock;
    using ClockFn = std::function<Clock::time_point()>;
    using TokenFn = std::function<std::string()>;

    static constexpr auto default_ttl = std::chrono::seconds(15);

    struct Grant {
        std::string token;
        std::string base_revision;
        std::string owner;
        Clock::time_point expires_at;
    };

    explicit CfgLease(ClockFn clock = {}, TokenFn token = {});

    // Return no grant while another unexpired lease is active.
    [[nodiscard]] std::optional<Grant> acquire(
        std::string base_revision,
        std::string owner,
        Clock::duration ttl = default_ttl);

    [[nodiscard]] bool valid(std::string const& token,
                             std::string const& base_revision);
    [[nodiscard]] bool release(std::string const& token);
    [[nodiscard]] std::optional<Grant> active();

private:
    // The caller holds lease_mutex_.
    void expire_locked();

    ClockFn clock_;
    TokenFn token_;
    std::mutex lease_mutex_;
    std::optional<Grant> active_;
};

}  // namespace sx::cfg
