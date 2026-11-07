#include <gtest/gtest.h>

#include <service/cfgapi/cfg_tx_basket.hpp>
#include <service/cfgapi/cfg_update.hpp>
#include <service/cfgapi/cfg_write_gate.hpp>

#include <chrono>
#include <mutex>

namespace tx = sx::cfg::tx;

namespace {

constexpr auto base_config = R"cfg(
settings = {
    enabled = true;
};
address_objects = {};
)cfg";

class CfgTxBasketTest : public testing::Test {
protected:
    CfgTxBasketTest()
        : gate(
              [this] { return now; },
              [] { return "transaction-token"; }),
          basket([this] { return now; }) {
        base = board.init_revision(base_config, "startup");
    }

    tx::Transaction::CreateResult transaction() {
        return tx::Transaction::create(
            board,
            gate,
            config_mutex,
            "gui-session",
            base.id,
            [](std::string const&) -> tx::Result<void> { return {}; });
    }

    sx::cfg::CfgLease::Clock::time_point now {};
    UpdateBoard board;
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;
    tx::TxBasket basket;
    sx::cfg::CfgRevision base;
};

}  // namespace

TEST_F(CfgTxBasketTest, KeepsPreparedSnapshotServerSideUntilCommit) {
    auto opened = basket.begin(transaction());
    ASSERT_TRUE(opened);
    EXPECT_EQ(opened->token, "transaction-token");
    EXPECT_EQ(opened->base_revision, base.id);
    EXPECT_EQ(opened->expires_in, sx::cfg::CfgLease::default_ttl);

    auto prepared = basket.prepare(
        opened->token,
        {tx::Set {"settings.enabled", false}});
    ASSERT_TRUE(prepared);
    EXPECT_EQ(prepared->operation_count, 1U);
    EXPECT_EQ(prepared->content_hash.rfind("sha256:", 0), 0U);

    auto committed = basket.commit(opened->token, "disable test setting");
    ASSERT_TRUE(committed);
    EXPECT_EQ(board.revision_current(), committed->revision);
    EXPECT_EQ(basket.size(), 0U);
    EXPECT_FALSE(gate.active());

    auto revision = board.revision(committed->revision);
    ASSERT_TRUE(revision);
    EXPECT_NE(revision->snapshot.find("enabled = false"), std::string::npos);
    EXPECT_EQ(revision->description, "disable test setting");
}

TEST_F(CfgTxBasketTest, AbortDestroysTransactionAndReleasesLease) {
    auto opened = basket.begin(transaction());
    ASSERT_TRUE(opened);
    EXPECT_TRUE(gate.active());

    EXPECT_TRUE(basket.abort(opened->token));

    EXPECT_EQ(basket.size(), 0U);
    EXPECT_FALSE(gate.active());
    auto committed = basket.commit(opened->token);
    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "unknown_transaction");
}

TEST_F(CfgTxBasketTest, ExpiredTransactionIsRemovedOnNextAccess) {
    auto opened = basket.begin(transaction());
    ASSERT_TRUE(opened);

    now += sx::cfg::CfgLease::default_ttl;

    EXPECT_EQ(basket.size(), 0U);
    EXPECT_FALSE(gate.active());
    auto prepared = basket.prepare(
        opened->token,
        {tx::Set {"settings.enabled", false}});
    ASSERT_FALSE(prepared);
    EXPECT_EQ(prepared.error().code, "unknown_transaction");
}

TEST_F(CfgTxBasketTest, FailedReprepareDiscardsOlderCandidate) {
    auto opened = basket.begin(transaction());
    ASSERT_TRUE(opened);
    ASSERT_TRUE(basket.prepare(
        opened->token,
        {tx::Set {"settings.enabled", false}}));

    auto failed = basket.prepare(
        opened->token,
        {tx::Set {"settings.enabled", std::string {"false"}}});
    ASSERT_FALSE(failed);
    EXPECT_EQ(failed.error().code, "type_mismatch");

    auto committed = basket.commit(opened->token);
    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "not_prepared");
    EXPECT_EQ(board.revision_current(), base.id);
}

TEST_F(CfgTxBasketTest, CommitRequiresPrepare) {
    auto opened = basket.begin(transaction());
    ASSERT_TRUE(opened);

    auto committed = basket.commit(opened->token);

    ASSERT_FALSE(committed);
    EXPECT_EQ(committed.error().code, "not_prepared");
    EXPECT_EQ(basket.size(), 1U);
    EXPECT_TRUE(gate.active());
}

TEST_F(CfgTxBasketTest, UsesConfiguredCandidatePreparation) {
    bool called = false;
    tx::TxBasket configured_basket {
        [this] { return now; },
        [&called](tx::Transaction& active, std::vector<tx::Op> operations) {
            called = true;
            return active.prepare(
                std::move(operations),
                [](tx::Add const&) -> tx::Candidate::AddInitializer {
                    return [](libconfig::Setting& collection, std::string const& name) {
                        auto& entry = collection.add(name, libconfig::Setting::TypeGroup);
                        entry.add("type", libconfig::Setting::TypeString) = "cidr";
                        return true;
                    };
                });
        },
    };
    auto opened = configured_basket.begin(transaction());
    ASSERT_TRUE(opened);

    auto prepared = configured_basket.prepare(
        opened->token,
        {tx::Add {"address_objects", "office"}});

    EXPECT_TRUE(called);
    ASSERT_TRUE(prepared);
    EXPECT_EQ(prepared->operation_count, 1U);
}
