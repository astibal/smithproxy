#include "cfg_tx_validate.hpp"

#include <utility>

#include <utils/crypto.hpp>

#include "cfg_update.hpp"
#include "cfg_write_gate.hpp"

namespace sx::cfg::tx {
namespace {

Issue transaction_issue(std::string code, std::string detail) {
    return Issue {
        Issue::no_operation,
        std::move(code),
        {},
        std::move(detail),
    };
}

}  // namespace

Transaction::Transaction(UpdateBoard& board, CfgWriteGate& gate, CfgLease::Grant lease)
    : board_(board), gate_(gate), lease_(std::move(lease)) {}

Transaction::Transaction(Transaction&& other) noexcept
    : board_(other.board_),
      gate_(other.gate_),
      lease_(std::move(other.lease_)),
      owns_lease_(other.owns_lease_) {
    other.owns_lease_ = false;
}

Transaction::~Transaction() {
    if(owns_lease_) (void)gate_.release(lease_.token);
}

Transaction::CreateResult Transaction::create(
    UpdateBoard& board,
    CfgWriteGate& gate,
    std::string owner) {
    return create(board, gate, std::move(owner), board.revision_current());
}

Transaction::CreateResult Transaction::create(
    UpdateBoard& board,
    CfgWriteGate& gate,
    std::string owner,
    std::string base_revision) {
    if(base_revision.empty()) {
        return transaction_issue("missing_base_revision", "Base revision must not be empty");
    }
    if(owner.empty()) {
        return transaction_issue("missing_owner", "Transaction owner must not be empty");
    }

    // Lease acquisition and revision comparison happen while ordinary writers
    // are stopped. A successful Transaction therefore starts on a stable base.
    auto grant = gate.acquire(
        base_revision,
        std::move(owner),
        [&board] { return board.revision_current(); });
    if(!grant) {
        if(board.revision_current() != base_revision) {
            return transaction_issue(
                "stale_revision", "Running configuration no longer matches the base revision");
        }
        return transaction_issue(
            "lease_busy", "Another configuration transaction holds the commit lease");
    }

    return Transaction(board, gate, std::move(*grant));
}

Result<Prepared> Transaction::prepare(Op operation) {
    std::vector<Op> operations;
    operations.push_back(std::move(operation));
    return prepare(std::move(operations));
}

Result<Prepared> Transaction::prepare(std::vector<Op> operations) {
    if(operations.empty()) {
        return transaction_issue("empty_transaction", "Transaction requires at least one operation");
    }

    auto revision = board_.revision(lease_.base_revision);
    if(!revision) {
        return transaction_issue(
            "revision_unavailable", "Base revision snapshot is no longer available");
    }

    auto candidate = Candidate::load(revision->snapshot);
    if(!candidate) return candidate.error();

    for(std::size_t index = 0; index < operations.size(); ++index) {
        auto applied = candidate->apply(operations[index], index);
        if(!applied) return applied.error();
    }

    auto snapshot = candidate->snapshot();
    if(!snapshot) return snapshot.error();

    auto hash = sx::crypto::sha256(*snapshot);
    if(!hash) {
        return transaction_issue(
            "hash_failed", "Validated candidate snapshot could not be hashed");
    }

    // Candidate construction may be expensive. Confirm that its lease and
    // base revision are still coherent before advertising it as prepared.
    if(!gate_.valid(
           lease_.token,
           lease_.base_revision,
           [this] { return board_.revision_current(); })) {
        return transaction_issue(
            "lease_expired", "Commit lease expired while the candidate was being prepared");
    }

    return Prepared {
        std::move(*snapshot),
        "sha256:" + std::move(*hash),
        operations.size(),
    };
}

CfgLease::Grant const& Transaction::lease() const noexcept {
    return lease_;
}

}  // namespace sx::cfg::tx
