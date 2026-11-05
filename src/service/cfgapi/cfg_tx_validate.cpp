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

Transaction::Transaction(
    UpdateBoard& board,
    CfgWriteGate& gate,
    std::recursive_mutex& config_mutex,
    CfgLease::Grant lease,
    ApplySnapshot apply_snapshot)
    : board_(board),
      gate_(gate),
      config_mutex_(config_mutex),
      lease_(std::move(lease)),
      apply_snapshot_(std::move(apply_snapshot)) {}

Transaction::Transaction(Transaction&& other) noexcept
    : board_(other.board_),
      gate_(other.gate_),
      config_mutex_(other.config_mutex_),
      lease_(std::move(other.lease_)),
      apply_snapshot_(std::move(other.apply_snapshot_)),
      owns_lease_(other.owns_lease_) {
    other.owns_lease_ = false;
}

Transaction::~Transaction() {
    if(owns_lease_) (void)gate_.release(lease_.token);
}

Transaction::CreateResult Transaction::create(
    UpdateBoard& board,
    CfgWriteGate& gate,
    std::recursive_mutex& config_mutex,
    std::string owner,
    ApplySnapshot apply_snapshot) {
    return create(
        board,
        gate,
        config_mutex,
        std::move(owner),
        board.revision_current(),
        std::move(apply_snapshot));
}

Transaction::CreateResult Transaction::create(
    UpdateBoard& board,
    CfgWriteGate& gate,
    std::recursive_mutex& config_mutex,
    std::string owner,
    std::string base_revision,
    ApplySnapshot apply_snapshot) {
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

    return Transaction(
        board, gate, config_mutex, std::move(*grant), std::move(apply_snapshot));
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
        lease_.token,
        std::move(*snapshot),
        "sha256:" + std::move(*hash),
        operations.size(),
    };
}

Result<Committed> Transaction::commit(Op operation, std::string description) {
    auto prepared = prepare(std::move(operation));
    if(!prepared) return prepared.error();
    return commit(std::move(*prepared), std::move(description));
}

Result<Committed> Transaction::commit(Prepared prepared, std::string description) {
    if(prepared.transaction_token != lease_.token) {
        return transaction_issue(
            "foreign_candidate", "Prepared candidate belongs to another transaction");
    }
    if(!apply_snapshot_) {
        return transaction_issue(
            "apply_unavailable", "Running configuration apply function is not configured");
    }

    auto hash = sx::crypto::sha256(prepared.snapshot);
    if(!hash || prepared.content_hash != "sha256:" + *hash) {
        return transaction_issue(
            "candidate_changed", "Prepared candidate content no longer matches its hash");
    }

    // enter() validates the token and base revision while taking the same
    // writer/config locks used by ordinary configuration mutations.
    auto guard = gate_.enter(config_mutex_, lease_.token, lease_.base_revision);
    if(!guard || board_.revision_current() != lease_.base_revision) {
        return transaction_issue(
            "lease_expired", "Commit lease or base revision is no longer valid");
    }

    auto applied = apply_snapshot_(prepared.snapshot);
    if(!applied) return applied.error();

    if(description.empty()) {
        description = "commit " + std::to_string(prepared.operation_count) +
                      " configuration operation(s)";
    }
    auto revision = board_.upgrade(
        lease_.owner, std::move(prepared.snapshot), std::move(description));
    const auto content_hash = std::move(prepared.content_hash);

    // Release the config/write locks before waking writers waiting on the
    // lease. The successful transaction no longer owns it afterwards.
    guard.reset();
    (void)gate_.release(lease_.token);
    owns_lease_ = false;

    return Committed {std::move(revision.id), content_hash};
}

CfgLease::Grant const& Transaction::lease() const noexcept {
    return lease_;
}

}  // namespace sx::cfg::tx
