#include "cfg_write_gate.hpp"

#include <stdexcept>
#include <utility>

namespace sx::cfg {
namespace {

class ConfigUnlockGuard {
public:
    explicit ConfigUnlockGuard(std::unique_lock<std::recursive_mutex>& config_lock)
        : config_lock_(config_lock) {
        config_lock_.unlock();
    }

    ~ConfigUnlockGuard() {
        config_lock_.lock();
    }

    ConfigUnlockGuard(ConfigUnlockGuard const&) = delete;
    ConfigUnlockGuard& operator=(ConfigUnlockGuard const&) = delete;

private:
    std::unique_lock<std::recursive_mutex>& config_lock_;
};

bool lease_allows(
    CfgLease& lease,
    std::string const* token,
    std::string const* base_revision) {
    if(token && base_revision) {
        return lease.valid(*token, *base_revision);
    }
    return !lease.active();
}

}  // namespace

CfgWriteGate::Guard::Guard(
    std::unique_lock<std::mutex> writer,
    std::unique_lock<std::recursive_mutex> config)
    : writer_(std::move(writer)), config_(std::move(config)) {}

bool CfgWriteGate::Guard::while_config_unlocked(UnlockedOp operation) {
    if(!operation) {
        throw std::invalid_argument("configuration write gate requires an unlocked operation");
    }

    ConfigUnlockGuard unlocked(config_);
    return operation();
}

CfgWriteGate::CfgWriteGate(CfgLease::ClockFn clock, CfgLease::TokenFn token)
    : clock_(clock ? std::move(clock) : [] { return CfgLease::Clock::now(); }),
      lease_(clock_, std::move(token)) {}

std::optional<CfgWriteGate::Guard> CfgWriteGate::enter(
    std::recursive_mutex& config_mutex) {
    return enter_locked(config_mutex, nullptr, nullptr);
}

std::optional<CfgWriteGate::Guard> CfgWriteGate::enter_wait(
    std::recursive_mutex& config_mutex,
    std::chrono::milliseconds progress_interval,
    WaitProgress progress) {
    if(progress_interval <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("configuration write wait interval must be positive");
    }
    if(!progress) {
        throw std::invalid_argument("configuration write wait requires a progress callback");
    }

    const auto started_at = clock_();
    auto next_progress = started_at + progress_interval;

    for(;;) {
        std::unique_lock control(control_mutex_, std::defer_lock);
        std::unique_lock writer(writer_mutex_, std::defer_lock);
        std::unique_lock config(config_mutex, std::defer_lock);
        std::lock(control, writer, config);

        if(lease_allows(lease_, nullptr, nullptr)) {
            control.unlock();
            return Guard(std::move(writer), std::move(config));
        }

        writer.unlock();
        config.unlock();

        const auto now = clock_();
        if(now >= next_progress) {
            control.unlock();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - started_at);
            if(!progress(elapsed)) return std::nullopt;
            next_progress = now + progress_interval;
            continue;
        }

        auto active_lease = lease_.active();
        const auto wake_at = active_lease
            ? std::min(next_progress, active_lease->expires_at)
            : next_progress;

        lease_changed_.wait_until(control, wake_at);
    }
}

std::optional<CfgWriteGate::Guard> CfgWriteGate::enter(
    std::recursive_mutex& config_mutex,
    std::string const& token,
    std::string const& base_revision) {
    return enter_locked(config_mutex, &token, &base_revision);
}

std::optional<CfgLease::Grant> CfgWriteGate::acquire(
    std::string base_revision,
    std::string owner,
    CurrentRevision current_revision,
    CfgLease::Clock::duration ttl) {
    if(!current_revision) {
        throw std::invalid_argument("configuration write gate requires a revision reader");
    }

    std::scoped_lock locks(control_mutex_, writer_mutex_);
    if(current_revision() != base_revision) return std::nullopt;
    return lease_.acquire(std::move(base_revision), std::move(owner), ttl);
}

bool CfgWriteGate::valid(
    std::string const& token,
    std::string const& base_revision,
    CurrentRevision current_revision) {
    if(!current_revision) {
        throw std::invalid_argument("configuration write gate requires a revision reader");
    }

    std::scoped_lock locks(control_mutex_, writer_mutex_);
    return lease_.valid(token, base_revision) && current_revision() == base_revision;
}

bool CfgWriteGate::release(std::string const& token) {
    bool released = false;
    {
        std::scoped_lock control(control_mutex_);
        released = lease_.release(token);
    }
    if(released) lease_changed_.notify_all();
    return released;
}

std::optional<CfgLease::Grant> CfgWriteGate::active() {
    std::scoped_lock control(control_mutex_);
    return lease_.active();
}

std::optional<CfgWriteGate::Guard> CfgWriteGate::enter_locked(
    std::recursive_mutex& config_mutex,
    std::string const* token,
    std::string const* base_revision) {
    std::unique_lock control(control_mutex_, std::defer_lock);
    std::unique_lock writer(writer_mutex_, std::defer_lock);
    std::unique_lock config(config_mutex, std::defer_lock);
    std::lock(control, writer, config);

    if(!lease_allows(lease_, token, base_revision)) return std::nullopt;

    control.unlock();
    return Guard(std::move(writer), std::move(config));
}

}  // namespace sx::cfg
