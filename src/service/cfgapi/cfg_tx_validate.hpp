#pragma once

#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "cfg_lease.hpp"
#include "cfg_tx.hpp"

class UpdateBoard;

namespace sx::cfg {
class CfgWriteGate;
}

namespace sx::cfg::tx {

// Server-side candidate prepared for commit. The candidate snapshot remains
// trusted server data and never needs to make a round trip through a client.
struct Prepared {
    std::string transaction_token;
    std::string snapshot;
    std::string content_hash;
    std::size_t operation_count {0};
};

struct Committed {
    std::string revision;
    std::string content_hash;
};

// A transaction owns its commit lease for its entire lifetime. Creating one
// reserves a stable base revision; destruction without commit releases it.
class Transaction {
public:
    using CreateResult = Result<Transaction>;
    using ApplySnapshot = std::function<Result<void>(std::string const& snapshot)>;

    Transaction(Transaction&& other) noexcept;
    Transaction& operator=(Transaction&&) = delete;
    Transaction(Transaction const&) = delete;
    Transaction& operator=(Transaction const&) = delete;
    ~Transaction();

    // Start on the current revision, or require a specific base revision for
    // callers which decoded it from an API request.
    static CreateResult create(
        UpdateBoard& board,
        CfgWriteGate& gate,
        std::recursive_mutex& config_mutex,
        std::string owner,
        ApplySnapshot apply_snapshot = {});
    static CreateResult create(
        UpdateBoard& board,
        CfgWriteGate& gate,
        std::recursive_mutex& config_mutex,
        std::string owner,
        std::string base_revision,
        ApplySnapshot apply_snapshot = {});

    // Apply and validate operations against the isolated base snapshot. A
    // successful result is ready for the later commit stage.
    Result<Prepared> prepare(Op operation);
    Result<Prepared> prepare(std::vector<Op> operations);
    Result<Prepared> prepare(Add operation, Candidate::AddInitializer initializer);

    // Apply one prepared candidate to running configuration. Persistence
    // remains an explicit, separate save-config operation.
    // The Op overload is the one-command convenience path: it prepares and
    // validates the operation before forwarding the result to the same commit.
    Result<Committed> commit(Op operation, std::string description = {});
    Result<Committed> commit(Add operation,
                             Candidate::AddInitializer initializer,
                             std::string description = {});
    Result<Committed> commit(Prepared prepared, std::string description = {});

    [[nodiscard]] CfgLease::Grant const& lease() const noexcept;

private:
    Transaction(
        UpdateBoard& board,
        CfgWriteGate& gate,
        std::recursive_mutex& config_mutex,
        CfgLease::Grant lease,
        ApplySnapshot apply_snapshot);

    Result<Prepared> finish_prepare(Candidate candidate, std::size_t operation_count);

    UpdateBoard& board_;
    CfgWriteGate& gate_;
    std::recursive_mutex& config_mutex_;
    CfgLease::Grant lease_;
    ApplySnapshot apply_snapshot_;
    bool owns_lease_ {true};
};

}  // namespace sx::cfg::tx
