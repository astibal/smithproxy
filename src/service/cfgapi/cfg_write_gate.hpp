#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

#include "cfg_lease.hpp"

namespace sx::cfg {

// Serializes configuration writers and keeps ordinary writers out while a
// commit lease is active.
class CfgWriteGate {
public:
    using CurrentRevision = std::function<std::string()>;
    using WaitProgress = std::function<bool(std::chrono::milliseconds)>;

    class Guard {
    public:
        using UnlockedOp = std::function<bool()>;

        Guard(Guard&&) noexcept = default;
        Guard& operator=(Guard&&) noexcept = default;
        Guard(Guard const&) = delete;
        Guard& operator=(Guard const&) = delete;

        // Temporarily release only the config mutex. The mutex is reacquired
        // before returning or propagating an exception.
        bool while_config_unlocked(UnlockedOp operation);

    private:
        friend class CfgWriteGate;

        Guard(std::unique_lock<std::mutex> writer,
              std::unique_lock<std::recursive_mutex> config);

        std::unique_lock<std::mutex> writer_;
        std::unique_lock<std::recursive_mutex> config_;
    };

    explicit CfgWriteGate(CfgLease::ClockFn clock = {}, CfgLease::TokenFn token = {});

    // Enter as an ordinary CLI/API writer. An active lease denies entry.
    [[nodiscard]] std::optional<Guard> enter(std::recursive_mutex& config_mutex);

    // Wait for an active lease to be released or expire. The callback runs at
    // the requested interval and returns false when the caller wants to stop.
    [[nodiscard]] std::optional<Guard> enter_wait(
        std::recursive_mutex& config_mutex,
        std::chrono::milliseconds progress_interval,
        WaitProgress progress);

    // Enter as the holder of a lease-bound transaction.
    [[nodiscard]] std::optional<Guard> enter(
        std::recursive_mutex& config_mutex,
        std::string const& token,
        std::string const& base_revision);

    // Stop writers, compare the requested base with the actual current
    // revision, then publish the lease as one gate operation.
    [[nodiscard]] std::optional<CfgLease::Grant> acquire(
        std::string base_revision,
        std::string owner,
        CurrentRevision current_revision,
        CfgLease::Clock::duration ttl = CfgLease::default_ttl);

    // Check the lease and its base revision as one gate operation while
    // ordinary writers are stopped.
    [[nodiscard]] bool valid(
        std::string const& token,
        std::string const& base_revision,
        CurrentRevision current_revision);

    [[nodiscard]] bool release(std::string const& token);
    [[nodiscard]] std::optional<CfgLease::Grant> active();

private:
    [[nodiscard]] std::optional<Guard> enter_locked(
        std::recursive_mutex& config_mutex,
        std::string const* token,
        std::string const* base_revision);

    CfgLease::ClockFn clock_;
    std::mutex control_mutex_;
    std::condition_variable lease_changed_;
    std::mutex writer_mutex_;
    CfgLease lease_;
};

}  // namespace sx::cfg
