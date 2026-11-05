#include "cfg_lease.hpp"

#include <stdexcept>
#include <utility>

#include <utils/crypto.hpp>

namespace sx::cfg {
namespace {

std::string random_token() {
    auto token = sx::crypto::random_hex(16);
    if(!token) {
        throw std::runtime_error("cannot generate configuration lease token");
    }
    return *token;
}

}  // namespace

CfgLease::CfgLease(ClockFn clock, TokenFn token)
    : clock_(clock ? std::move(clock) : [] { return Clock::now(); }),
      token_(token ? std::move(token) : random_token) {}

std::optional<CfgLease::Grant> CfgLease::acquire(
    std::string base_revision,
    std::string owner,
    Clock::duration ttl) {
    if(base_revision.empty()) {
        throw std::invalid_argument("configuration lease requires a base revision");
    }
    if(owner.empty()) {
        throw std::invalid_argument("configuration lease requires an owner");
    }
    if(ttl <= Clock::duration::zero()) {
        throw std::invalid_argument("configuration lease TTL must be positive");
    }

    std::scoped_lock lock(lease_mutex_);
    expire_locked();
    if(active_) return std::nullopt;

    auto token_value = token_();
    if(token_value.empty()) {
        throw std::runtime_error("configuration lease token must not be empty");
    }
    active_ = Grant {
        std::move(token_value),
        std::move(base_revision),
        std::move(owner),
        clock_() + ttl,
    };
    return active_;
}

bool CfgLease::valid(std::string const& token, std::string const& base_revision) {
    std::scoped_lock lock(lease_mutex_);
    expire_locked();
    return active_ && active_->token == token && active_->base_revision == base_revision;
}

bool CfgLease::release(std::string const& token) {
    std::scoped_lock lock(lease_mutex_);
    expire_locked();
    if(!active_ || active_->token != token) return false;

    active_.reset();
    return true;
}

std::optional<CfgLease::Grant> CfgLease::active() {
    std::scoped_lock lock(lease_mutex_);
    expire_locked();
    return active_;
}

void CfgLease::expire_locked() {
    if(active_ && clock_() >= active_->expires_at) {
        active_.reset();
    }
}

}  // namespace sx::cfg
