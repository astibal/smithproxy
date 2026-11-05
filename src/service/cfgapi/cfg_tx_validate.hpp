#pragma once

#include <cstddef>
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
    std::string snapshot;
    std::string content_hash;
    std::size_t operation_count {0};
};

// A transaction owns its commit lease for its entire lifetime. Creating one
// reserves a stable base revision; destruction without commit releases it.
class Transaction {
public:
    using CreateResult = Result<Transaction>;

    Transaction(Transaction&& other) noexcept;
    Transaction& operator=(Transaction&&) = delete;
    Transaction(Transaction const&) = delete;
    Transaction& operator=(Transaction const&) = delete;
    ~Transaction();

    // Start on the current revision, or require a specific base revision for
    // callers which decoded it from an API request.
    static CreateResult create(UpdateBoard& board, CfgWriteGate& gate, std::string owner);
    static CreateResult create(
        UpdateBoard& board,
        CfgWriteGate& gate,
        std::string owner,
        std::string base_revision);

    // Apply and validate operations against the isolated base snapshot. A
    // successful result is ready for the later commit stage.
    Result<Prepared> prepare(Op operation);
    Result<Prepared> prepare(std::vector<Op> operations);

    [[nodiscard]] CfgLease::Grant const& lease() const noexcept;

private:
    Transaction(UpdateBoard& board, CfgWriteGate& gate, CfgLease::Grant lease);

    UpdateBoard& board_;
    CfgWriteGate& gate_;
    CfgLease::Grant lease_;
    bool owns_lease_ {true};
};

}  // namespace sx::cfg::tx
