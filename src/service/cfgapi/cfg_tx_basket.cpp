#include "cfg_tx_basket.hpp"
#include "cfg_log.hpp"

#include <algorithm>
#include <utility>

namespace sx::cfg::tx {

TxBasket::TxBasket(ClockFn clock, PrepareFn prepare)
    : clock_(clock ? std::move(clock) : [] { return Clock::now(); }),
      prepare_(prepare ? std::move(prepare)
                       : [](Transaction& transaction, std::vector<Op> operations) {
                             return transaction.prepare(std::move(operations));
                         }) {}

Result<TxBasket::Opened> TxBasket::begin(Transaction::CreateResult transaction) {
    config_log().inf("configuration transaction begin requested");
    if(!transaction) {
        config_log().war("configuration transaction begin rejected: %s",
                         transaction.error().code.c_str());
        return transaction.error();
    }

    // The Transaction already owns its lease. Moving it into the basket keeps
    // that lease alive after the begin HTTP request has returned.
    std::lock_guard lock(mutex_);
    expire_locked();

    const auto token = transaction->lease().token;
    auto [entry, inserted] = entries_.emplace(token, Entry {std::move(*transaction)});
    if(!inserted) {
        config_log().war("configuration transaction begin rejected: duplicate lease token");
        return basket_issue(
            "duplicate_transaction", "Commit lease token is already registered");
    }

    config_log().noti("configuration transaction opened: active=%zu", entries_.size());
    return Opened {
        token,
        entry->second.transaction.lease().base_revision,
        remaining(entry->second),
    };
}

Result<TxBasket::PreparedInfo> TxBasket::prepare(std::string const& token,
                                                std::vector<Op> operations) {
    config_log().inf("configuration transaction prepare requested: operations=%zu",
                     operations.size());
    // There is only one global commit lease today, so serializing basket
    // operations does not reduce useful concurrency. It does make lookup,
    // expiration, and candidate replacement one indivisible operation.
    std::lock_guard lock(mutex_);
    expire_locked();

    auto entry = entries_.find(token);
    if(entry == entries_.end()) {
        config_log().war("configuration transaction prepare rejected: token is unknown or expired");
        return basket_issue(
            "unknown_transaction", "Transaction does not exist or its lease expired");
    }

    // A failed re-prepare must not leave an older candidate available for a
    // later commit under the same token.
    entry->second.prepared.reset();
    auto prepared = prepare_(entry->second.transaction, std::move(operations));
    if(!prepared) {
        config_log().war("configuration transaction prepare rejected: %s",
                         prepared.error().code.c_str());
        return prepared.error();
    }

    PreparedInfo info {
        prepared->content_hash,
        prepared->operation_count,
        remaining(entry->second),
    };
    // Keep the complete trusted snapshot on the server. The HTTP client sees
    // only PreparedInfo and later refers to this candidate by token.
    entry->second.prepared = std::move(*prepared);
    config_log().noti("configuration transaction prepared: operations=%zu",
                      info.operation_count);
    return info;
}

Result<Committed> TxBasket::commit(std::string const& token, std::string description) {
    config_log().inf("configuration transaction commit requested");
    std::lock_guard lock(mutex_);
    expire_locked();

    auto entry = entries_.find(token);
    if(entry == entries_.end()) {
        config_log().war("configuration transaction commit rejected: token is unknown or expired");
        return basket_issue(
            "unknown_transaction", "Transaction does not exist or its lease expired");
    }
    if(!entry->second.prepared) {
        config_log().war("configuration transaction commit rejected: transaction is not prepared");
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
    if(!committed) {
        config_log().war("configuration transaction commit rejected: %s",
                         committed.error().code.c_str());
        return committed.error();
    }

    // Successful Transaction::commit has already released the lease. Erasing
    // its now-empty basket entry completes the server-side lifecycle.
    Committed result = std::move(*committed);
    entries_.erase(entry);
    config_log().noti("configuration transaction committed: active=%zu", entries_.size());
    return result;
}

Result<void> TxBasket::abort(std::string const& token) {
    config_log().inf("configuration transaction abort requested");
    std::lock_guard lock(mutex_);
    expire_locked();

    auto entry = entries_.find(token);
    if(entry == entries_.end()) {
        config_log().war("configuration transaction abort rejected: token is unknown or expired");
        return basket_issue(
            "unknown_transaction", "Transaction does not exist or its lease expired");
    }
    // Erasing destroys Transaction. Its RAII destructor releases any lease
    // which has not already expired or been committed.
    entries_.erase(entry);
    config_log().noti("configuration transaction aborted: active=%zu", entries_.size());
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
    std::size_t expired = 0;
    for(auto entry = entries_.begin(); entry != entries_.end();) {
        if(now >= entry->second.transaction.lease().expires_at) {
            entry = entries_.erase(entry);
            ++expired;
        } else {
            ++entry;
        }
    }
    if(expired > 0) {
        config_log().noti("expired configuration transactions removed: count=%zu active=%zu",
                          expired, entries_.size());
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
