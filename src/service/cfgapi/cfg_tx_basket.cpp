#include "cfg_tx_basket.hpp"

#include <algorithm>
#include <utility>

namespace sx::cfg::tx {

TxBasket::TxBasket(ClockFn clock)
    : clock_(clock ? std::move(clock) : [] { return Clock::now(); }) {}

Result<TxBasket::Opened> TxBasket::begin(Transaction::CreateResult transaction) {
    if(!transaction) return transaction.error();

    // The Transaction already owns its lease. Moving it into the basket keeps
    // that lease alive after the begin HTTP request has returned.
    std::lock_guard lock(mutex_);
    expire_locked();

    const auto token = transaction->lease().token;
    auto [entry, inserted] = entries_.emplace(token, Entry {std::move(*transaction)});
    if(!inserted) {
        return basket_issue(
            "duplicate_transaction", "Commit lease token is already registered");
    }

    return Opened {
        token,
        entry->second.transaction.lease().base_revision,
        remaining(entry->second),
    };
}

Result<TxBasket::PreparedInfo> TxBasket::prepare(std::string const& token,
                                                std::vector<Op> operations) {
    // There is only one global commit lease today, so serializing basket
    // operations does not reduce useful concurrency. It does make lookup,
    // expiration, and candidate replacement one indivisible operation.
    std::lock_guard lock(mutex_);
    expire_locked();

    auto entry = entries_.find(token);
    if(entry == entries_.end()) {
        return basket_issue(
            "unknown_transaction", "Transaction does not exist or its lease expired");
    }

    // A failed re-prepare must not leave an older candidate available for a
    // later commit under the same token.
    entry->second.prepared.reset();
    auto prepared = entry->second.transaction.prepare(std::move(operations));
    if(!prepared) return prepared.error();

    PreparedInfo info {
        prepared->content_hash,
        prepared->operation_count,
        remaining(entry->second),
    };
    // Keep the complete trusted snapshot on the server. The HTTP client sees
    // only PreparedInfo and later refers to this candidate by token.
    entry->second.prepared = std::move(*prepared);
    return info;
}

Result<Committed> TxBasket::commit(std::string const& token, std::string description) {
    std::lock_guard lock(mutex_);
    expire_locked();

    auto entry = entries_.find(token);
    if(entry == entries_.end()) {
        return basket_issue(
            "unknown_transaction", "Transaction does not exist or its lease expired");
    }
    if(!entry->second.prepared) {
        return basket_issue(
            "not_prepared", "Transaction has no prepared candidate to commit");
    }

    // Consume the candidate before commit. If runtime apply fails, the lease
    // remains active but the client must prepare again; an already attempted
    // snapshot can never be committed accidentally by a retry.
    auto prepared = std::move(*entry->second.prepared);
    entry->second.prepared.reset();
    auto committed = entry->second.transaction.commit(
        std::move(prepared), std::move(description));
    if(!committed) return committed.error();

    // Successful Transaction::commit has already released the lease. Erasing
    // its now-empty basket entry completes the server-side lifecycle.
    Committed result = std::move(*committed);
    entries_.erase(entry);
    return result;
}

Result<void> TxBasket::abort(std::string const& token) {
    std::lock_guard lock(mutex_);
    expire_locked();

    auto entry = entries_.find(token);
    if(entry == entries_.end()) {
        return basket_issue(
            "unknown_transaction", "Transaction does not exist or its lease expired");
    }
    // Erasing destroys Transaction. Its RAII destructor releases any lease
    // which has not already expired or been committed.
    entries_.erase(entry);
    return {};
}

std::size_t TxBasket::size() {
    std::lock_guard lock(mutex_);
    expire_locked();
    return entries_.size();
}

void TxBasket::expire_locked() {
    // Lazy expiration avoids a maintenance thread. Every public operation
    // passes through this point, while CfgLease independently rejects an
    // expired token even if the basket has not been touched meanwhile.
    const auto now = clock_();
    for(auto entry = entries_.begin(); entry != entries_.end();) {
        if(now >= entry->second.transaction.lease().expires_at) {
            entry = entries_.erase(entry);
        } else {
            ++entry;
        }
    }
}

std::chrono::milliseconds TxBasket::remaining(Entry const& entry) const {
    const auto duration = entry.transaction.lease().expires_at - clock_();
    return std::max(
        std::chrono::milliseconds {0},
        std::chrono::duration_cast<std::chrono::milliseconds>(duration));
}

Issue TxBasket::basket_issue(std::string code, std::string detail) {
    return Issue {
        Issue::no_operation,
        std::move(code),
        {},
        std::move(detail),
    };
}

}  // namespace sx::cfg::tx
