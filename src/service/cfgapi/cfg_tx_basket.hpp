#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "cfg_tx_validate.hpp"

namespace sx::cfg::tx {

// A short-lived basket carrying one prepared change between HTTP requests.
// Candidate snapshots never leave the basket; clients refer to them only by
// their transaction token. Commit, abort, and timeout all empty the basket.
class TxBasket {
public:
    using Clock = CfgLease::Clock;
    using ClockFn = std::function<Clock::time_point()>;

    struct Opened {
        std::string token;
        std::string base_revision;
        std::chrono::milliseconds expires_in;
    };

    struct PreparedInfo {
        std::string content_hash;
        std::size_t operation_count {0};
        std::chrono::milliseconds expires_in;
    };

    explicit TxBasket(ClockFn clock = {});

    // Take ownership of a newly leased transaction and return the opaque
    // token which connects subsequent HTTP requests to this basket entry.
    Result<Opened> begin(Transaction::CreateResult transaction);

    // Replace any earlier candidate with one prepared from these operations.
    // Only verification metadata leaves the basket.
    Result<PreparedInfo> prepare(std::string const& token, std::vector<Op> operations);

    // Consume the prepared candidate. Success removes the complete entry;
    // failure keeps the transaction lease but requires another prepare.
    Result<Committed> commit(std::string const& token, std::string description = {});

    // Drop candidate and transaction together. Transaction destruction
    // releases its lease through RAII.
    Result<void> abort(std::string const& token);

    [[nodiscard]] std::size_t size();

private:
    struct Entry {
        explicit Entry(Transaction value) : transaction(std::move(value)) {}

        Transaction transaction;
        std::optional<Prepared> prepared;
    };

    void expire_locked();
    [[nodiscard]] std::chrono::milliseconds remaining(Entry const& entry) const;
    static Issue basket_issue(std::string code, std::string detail);

    ClockFn clock_;
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};

}  // namespace sx::cfg::tx
