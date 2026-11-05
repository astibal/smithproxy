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
    auto transaction = tx::Transaction::create(board, gate, "gui", revision.id);

    ASSERT_TRUE(transaction);
    auto result = transaction->prepare(request(revision.id).operations);

    ASSERT_TRUE(result);
    EXPECT_EQ(transaction->lease().token, "lease-token");
    EXPECT_EQ(transaction->lease().base_revision, revision.id);
    EXPECT_EQ(result->operation_count, 3U);
    EXPECT_NE(result->snapshot.find("192.0.2.0/24"), std::string::npos);
    EXPECT_EQ(result->content_hash.rfind("sha256:", 0), 0U);

    std::recursive_mutex config_mutex;
    EXPECT_FALSE(gate.enter(config_mutex));
    EXPECT_TRUE(gate.enter(config_mutex, transaction->lease().token, revision.id));
}

TEST(CfgTransaction, ConvenienceSetUsesCurrentRevisionAndBoundOwner) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    auto transaction = tx::Transaction::create(board, gate, "cli-session-1");

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
    auto result = tx::Transaction::create(board, gate, "gui", first.id);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "stale_revision");
}

TEST(CfgTransaction, ReportsBusyLeaseAtCreation) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "first-token"; });
    ASSERT_TRUE(gate.acquire(revision.id, "cli", [&] { return board.revision_current(); }));
    auto result = tx::Transaction::create(board, gate, "gui", revision.id);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "lease_busy");
}

TEST(CfgTransaction, KeepsLeaseAfterOperationFailureUntilDestruction) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    auto invalid = request(revision.id);
    invalid.operations.push_back(tx::Set {"settings.enabled", std::string {"false"}});

    {
        auto transaction = tx::Transaction::create(board, gate, "gui", revision.id);
        ASSERT_TRUE(transaction);
        auto result = transaction->prepare(std::move(invalid.operations));

        ASSERT_FALSE(result);
        EXPECT_EQ(result.error().operation, 3U);
        EXPECT_EQ(result.error().code, "type_mismatch");
        EXPECT_TRUE(gate.active());
    }
    EXPECT_FALSE(gate.active());

    std::recursive_mutex config_mutex;
    EXPECT_TRUE(gate.enter(config_mutex));
}

TEST(CfgTransaction, RejectsEmptyOperationsButKeepsTransactionLease) {
    UpdateBoard board;
    auto revision = board.init_revision(base_config, "startup");
    sx::cfg::CfgWriteGate gate;
    auto transaction = tx::Transaction::create(board, gate, "gui", revision.id);

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
    auto transaction = tx::Transaction::create(board, gate, "gui", revision.id);

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
    auto transaction = tx::Transaction::create(board, gate, "gui", revision.id);
    ASSERT_TRUE(transaction);

    now += sx::cfg::CfgLease::default_ttl;
    auto result = transaction->prepare(tx::Set {"settings.enabled", false});

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "lease_expired");
}
