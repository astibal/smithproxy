#include <gtest/gtest.h>

#include <service/cfgapi/cfg_tx_validate.hpp>
#include <service/cfgapi/cfg_update.hpp>
#include <service/cfgapi/cfg_write_gate.hpp>

#include <chrono>
#include <mutex>

namespace tx = sx::cfg::tx;
using namespace std::chrono_literals;

namespace {

constexpr auto base_config = R"cfg(
settings = {
    enabled = true;
};
address_objects = {};
policy = (
    { name = "first"; },
    { name = "second"; },
    { name = "third"; }
);
)cfg";

tx::Request request(std::string revision) {
    return tx::Request {
        std::move(revision),
        "gui",
        {
            tx::Add {"address_objects", "office"},
            tx::Set {"address_objects.office.type", std::string {"cidr"}},
            tx::Set {"address_objects.office.value", std::string {"192.0.2.0/24"}},
        },
    };
}

}  // namespace

TEST(CfgTransaction, PreparesCandidateAndKeepsLease) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(board, gate, config_mutex, "gui", revision.id);

    ASSERT_TRUE(transaction);
    auto result = transaction->prepare(request(revision.id).operations);

    ASSERT_TRUE(result);
    EXPECT_EQ(transaction->lease().token, "lease-token");
    EXPECT_EQ(transaction->lease().base_revision, revision.id);
    EXPECT_EQ(result->operation_count, 3U);
    EXPECT_NE(result->snapshot.find("192.0.2.0/24"), std::string::npos);
    EXPECT_EQ(result->content_hash.rfind("sha256:", 0), 0U);

    EXPECT_FALSE(gate.enter(config_mutex));
    EXPECT_TRUE(gate.enter(config_mutex, transaction->lease().token, revision.id));
}

TEST(CfgTransaction, ConvenienceSetUsesCurrentRevisionAndBoundOwner) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(board, gate, config_mutex, "cli-session-1");

    ASSERT_TRUE(transaction);
    auto result = transaction->prepare(tx::Set {"settings.enabled", false});

    ASSERT_TRUE(result);
    EXPECT_EQ(transaction->lease().base_revision, revision.id);
    EXPECT_EQ(transaction->lease().owner, "cli-session-1");
    EXPECT_EQ(result->operation_count, 1U);
}

TEST(CfgTransaction, RejectsStaleRevisionAtCreation) {
    UpdateBoard board;
    auto first = board.init_revision(base_config, "startup");
    board.upgrade("cli", base_config, "change");
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;
    auto result = tx::Transaction::create(board, gate, config_mutex, "gui", first.id);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "stale_revision");
}

TEST(CfgTransaction, ReportsBusyLeaseAtCreation) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "first-token"; });
    ASSERT_TRUE(gate.acquire(revision.id, "cli", [&] { return board.revision_current(); }));
    std::recursive_mutex config_mutex;
    auto result = tx::Transaction::create(board, gate, config_mutex, "gui", revision.id);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "lease_busy");
}

TEST(CfgTransaction, KeepsLeaseAfterOperationFailureUntilDestruction) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto invalid = request(revision.id);
    invalid.operations.push_back(tx::Set {"settings.enabled", std::string {"false"}});

    {
        auto transaction = tx::Transaction::create(
            board, gate, config_mutex, "gui", revision.id);
        ASSERT_TRUE(transaction);
        auto result = transaction->prepare(std::move(invalid.operations));

        ASSERT_FALSE(result);
        EXPECT_EQ(result.error().operation, 3U);
        EXPECT_EQ(result.error().code, "type_mismatch");
        EXPECT_TRUE(gate.active());
    }
    EXPECT_FALSE(gate.active());

    EXPECT_TRUE(gate.enter(config_mutex));
}

TEST(CfgTransaction, RejectsEmptyOperationsButKeepsTransactionLease) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(board, gate, config_mutex, "gui", revision.id);

    ASSERT_TRUE(transaction);
    auto result = transaction->prepare(std::vector<tx::Op> {});

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().operation, tx::Issue::no_operation);
    EXPECT_EQ(result.error().code, "empty_transaction");
    EXPECT_TRUE(gate.active());
}

TEST(CfgTransaction, KeepsLeaseWhenSnapshotCannotBeParsed) {
    UpdateBoard board;
    auto revision = board.init_revision("settings = {", "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(board, gate, config_mutex, "gui", revision.id);

    ASSERT_TRUE(transaction);
    auto result = transaction->prepare(request(revision.id).operations);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "invalid_snapshot");
    EXPECT_TRUE(gate.active());
}

TEST(CfgTransaction, RejectsPreparedCandidateAfterLeaseExpires) {
    auto now = sx::cfg::CfgLease::Clock::time_point {};
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate(
        [&now] { return now; },
        [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(board, gate, config_mutex, "gui", revision.id);
    ASSERT_TRUE(transaction);

    now += sx::cfg::CfgLease::default_ttl;
    auto result = transaction->prepare(tx::Set {"settings.enabled", false});

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "lease_expired");
}

TEST(CfgTransaction, CommitsPreparedCandidateAndReleasesLease) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    std::string applied_snapshot;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "gui-session-1",
        base.id,
        [&applied_snapshot](std::string const& snapshot) -> tx::Result<void> {
            applied_snapshot = snapshot;
            return {};
        });
    ASSERT_TRUE(transaction);
    auto prepared = transaction->prepare(tx::Set {"settings.enabled", false});
    ASSERT_TRUE(prepared);

    auto committed = transaction->commit(std::move(*prepared), "disable test setting");

    ASSERT_TRUE(committed);
    EXPECT_EQ(committed->content_hash.rfind("sha256:", 0), 0U);
    EXPECT_EQ(board.revision_current(), committed->revision);
    EXPECT_TRUE(board.unsaved());
    EXPECT_FALSE(gate.active());
    EXPECT_NE(applied_snapshot.find("enabled = false"), std::string::npos);
    auto revision = board.revision(committed->revision);
    ASSERT_TRUE(revision);
    EXPECT_EQ(revision->parent_id, base.id);
    EXPECT_EQ(revision->source, "gui-session-1");
    EXPECT_EQ(revision->description, "disable test setting");
}

TEST(CfgTransaction, ConvenienceCommitPreparesOneOperation) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "cli-session-1",
        base.id,
        [](std::string const&) -> tx::Result<void> { return {}; });
    ASSERT_TRUE(transaction);

    auto committed = transaction->commit(
        tx::Set {"settings.enabled", false}, "set settings.enabled");

    ASSERT_TRUE(committed);
    auto revision = board.revision(committed->revision);
    ASSERT_TRUE(revision);
    EXPECT_EQ(revision->description, "set settings.enabled");
    EXPECT_NE(revision->snapshot.find("enabled = false"), std::string::npos);
}

TEST(CfgTransaction, ConvenienceCommitRemovesAndMovesListEntries) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    const auto apply = [](std::string const&) -> tx::Result<void> { return {}; };

    auto remove = tx::Transaction::create(
        board, gate, config_mutex, "cli-session-1", base.id, apply);
    ASSERT_TRUE(remove);
    auto removed = remove->commit(tx::Remove {"policy", {"1"}}, "remove policy entry");
    ASSERT_TRUE(removed);

    auto move = tx::Transaction::create(
        board, gate, config_mutex, "cli-session-1", removed->revision, apply);
    ASSERT_TRUE(move);
    auto moved = move->commit(
        tx::Move {"policy", 1, tx::Position::before, 0}, "move policy [1] top");
    ASSERT_TRUE(moved);

    auto revision = board.revision(moved->revision);
    ASSERT_TRUE(revision);
    const auto third = revision->snapshot.find("third");
    const auto first = revision->snapshot.find("first");
    EXPECT_NE(third, std::string::npos);
    EXPECT_NE(first, std::string::npos);
    EXPECT_LT(third, first);
    EXPECT_EQ(revision->snapshot.find("second"), std::string::npos);
}

TEST(CfgTransaction, LocalAddInitializerBuildsDefaultsInsideCandidate) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "cli-session-1",
        base.id,
        [](std::string const&) -> tx::Result<void> { return {}; });
    ASSERT_TRUE(transaction);

    auto committed = transaction->commit(
        tx::Add {"address_objects", "office"},
        [](libconfig::Setting& collection, std::string const& name) {
            auto& entry = collection.add(name, libconfig::Setting::TypeGroup);
            entry.add("type", libconfig::Setting::TypeString) = "cidr";
            entry.add("value", libconfig::Setting::TypeString) = "192.0.2.0/24";
            return true;
        },
        "add address_objects.office");

    ASSERT_TRUE(committed);
    auto revision = board.revision(committed->revision);
    ASSERT_TRUE(revision);
    EXPECT_NE(revision->snapshot.find("office"), std::string::npos);
    EXPECT_NE(revision->snapshot.find("192.0.2.0/24"), std::string::npos);
}

TEST(CfgTransaction, FailedLocalAddInitializerKeepsBaseRevision) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    bool applied = false;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "cli-session-1",
        base.id,
        [&applied](std::string const&) -> tx::Result<void> {
            applied = true;
            return {};
        });
    ASSERT_TRUE(transaction);

    auto committed = transaction->commit(
        tx::Add {"address_objects", "office"},
        [](libconfig::Setting&, std::string const&) { return false; });

    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "initialization_failed");
    EXPECT_EQ(board.revision_current(), base.id);
    EXPECT_FALSE(applied);
    EXPECT_TRUE(gate.active());
}

TEST(CfgTransaction, RejectsChangedCandidateBeforeApply) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    bool applied = false;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "gui",
        base.id,
        [&applied](std::string const&) -> tx::Result<void> {
            applied = true;
            return {};
        });
    ASSERT_TRUE(transaction);
    auto prepared = transaction->prepare(tx::Set {"settings.enabled", false});
    ASSERT_TRUE(prepared);
    prepared->snapshot += "\n// changed after validation";

    auto committed = transaction->commit(std::move(*prepared));

    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "candidate_changed");
    EXPECT_FALSE(applied);
    EXPECT_EQ(board.revision_current(), base.id);
    EXPECT_TRUE(gate.active());
}

TEST(CfgTransaction, KeepsLeaseWhenApplyFails) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "gui",
        base.id,
        [](std::string const&) -> tx::Result<void> {
            return tx::Issue {
                tx::Issue::no_operation,
                "runtime_apply_failed",
                {},
                "Candidate could not be applied to the running configuration",
            };
        });
    ASSERT_TRUE(transaction);
    auto prepared = transaction->prepare(tx::Set {"settings.enabled", false});
    ASSERT_TRUE(prepared);

    auto committed = transaction->commit(std::move(*prepared));

    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "runtime_apply_failed");
    EXPECT_EQ(board.revision_current(), base.id);
    EXPECT_TRUE(gate.active());
}

TEST(CfgTransaction, RejectsCandidateFromAnotherTransaction) {
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "gui",
        base.id,
        [](std::string const&) -> tx::Result<void> { return {}; });
    ASSERT_TRUE(transaction);
    auto prepared = transaction->prepare(tx::Set {"settings.enabled", false});
    ASSERT_TRUE(prepared);
    prepared->transaction_token = "another-transaction";

    auto committed = transaction->commit(std::move(*prepared));

    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "foreign_candidate");
    EXPECT_EQ(board.revision_current(), base.id);
}

TEST(CfgTransaction, RejectsCommitAfterLeaseExpires) {
    auto now = sx::cfg::CfgLease::Clock::time_point {};
    UpdateBoard board;
    auto base = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate(
        [&now] { return now; },
        [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    bool applied = false;
    auto transaction = tx::Transaction::create(
        board,
        gate,
        config_mutex,
        "gui",
        base.id,
        [&applied](std::string const&) -> tx::Result<void> {
            applied = true;
            return {};
        });
    ASSERT_TRUE(transaction);
    auto prepared = transaction->prepare(tx::Set {"settings.enabled", false});
    ASSERT_TRUE(prepared);
    now += sx::cfg::CfgLease::default_ttl;

    auto committed = transaction->commit(std::move(*prepared));

    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "lease_expired");
    EXPECT_FALSE(applied);
    EXPECT_EQ(board.revision_current(), base.id);
}
