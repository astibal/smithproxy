#include <gtest/gtest.h>

#include <service/cfgapi/cfg_tx.hpp>

#include <limits>

namespace tx = sx::cfg::tx;

namespace {

constexpr auto base_config = R"cfg(
settings = {
    enabled = true;
    workers = 2;
    ports = [ 80, 443 ];
};
address_objects = {
    existing = {
        type = "cidr";
        value = "192.0.2.1/32";
    };
};
policy = (
    { name = "first"; },
    { name = "second"; },
    { name = "third"; }
);
)cfg";

tx::Candidate candidate() {
    auto loaded = tx::Candidate::load(base_config);
    EXPECT_TRUE(loaded);
    return std::move(*loaded);
}

}  // namespace

TEST(CfgTxCandidate, RejectsInvalidSnapshot) {
    auto loaded = tx::Candidate::load("settings = {");

    ASSERT_FALSE(loaded);
    EXPECT_EQ(loaded.error().code, "invalid_snapshot");
}

TEST(CfgTxCandidate, AppliesChainedAddAndSet) {
    auto value = candidate();

    ASSERT_TRUE(value.apply(tx::Add {"address_objects", "office"}, 0));
    ASSERT_TRUE(value.apply(tx::Set {"address_objects.office.type", std::string {"cidr"}}, 1));
    ASSERT_TRUE(value.apply(tx::Set {
        "address_objects.office.value", std::string {"198.51.100.0/24"}}, 2));

    auto snapshot = value.snapshot();
    ASSERT_TRUE(snapshot);
    EXPECT_TRUE(value.config().lookup("address_objects").exists("office"));
    EXPECT_NE(snapshot->find("198.51.100.0/24"), std::string::npos);
}

TEST(CfgTxCandidate, SetsScalarValues) {
    auto value = candidate();

    ASSERT_TRUE(value.apply(tx::Set {"settings.enabled", false}, 0));
    ASSERT_TRUE(value.apply(tx::Set {"settings.workers", std::int64_t {8}}, 1));

    EXPECT_FALSE(static_cast<bool>(value.config().lookup("settings.enabled")));
    EXPECT_EQ(static_cast<int>(value.config().lookup("settings.workers")), 8);
}

TEST(CfgTxCandidate, ReplacesTypedArray) {
    auto value = candidate();

    ASSERT_TRUE(value.apply(tx::Set {
        "settings.ports", std::vector<std::int64_t> {8080, 8443}}, 0));

    auto const& ports = value.config().lookup("settings.ports");
    ASSERT_EQ(ports.getLength(), 2);
    EXPECT_EQ(static_cast<int>(ports[0]), 8080);
    EXPECT_EQ(static_cast<int>(ports[1]), 8443);
}

TEST(CfgTxCandidate, FailedArrayReplacementKeepsPreviousValue) {
    auto value = candidate();

    auto result = value.apply(tx::Set {
        "settings.ports",
        std::vector<std::int64_t> {std::numeric_limits<std::int64_t>::max()}}, 2);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "type_mismatch");
    auto const& ports = value.config().lookup("settings.ports");
    ASSERT_EQ(ports.getLength(), 2);
    EXPECT_EQ(static_cast<int>(ports[0]), 80);
}

TEST(CfgTxCandidate, RemovesNamedAndListEntries) {
    auto value = candidate();

    ASSERT_TRUE(value.apply(tx::Remove {"address_objects", {"existing"}}, 0));
    ASSERT_TRUE(value.apply(tx::Remove {"policy", {"0", "2"}}, 1));

    EXPECT_FALSE(value.config().lookup("address_objects").exists("existing"));
    auto const& policy = value.config().lookup("policy");
    ASSERT_EQ(policy.getLength(), 1);
    EXPECT_STREQ(static_cast<char const*>(policy[0]["name"]), "second");
}

TEST(CfgTxCandidate, MovesListEntry) {
    auto value = candidate();

    ASSERT_TRUE(value.apply(tx::Move {"policy", 0, tx::Position::after, 2}, 0));

    auto const& policy = value.config().lookup("policy");
    EXPECT_STREQ(static_cast<char const*>(policy[0]["name"]), "second");
    EXPECT_STREQ(static_cast<char const*>(policy[1]["name"]), "third");
    EXPECT_STREQ(static_cast<char const*>(policy[2]["name"]), "first");
}

TEST(CfgTxCandidate, RejectsMismatchedValueType) {
    auto value = candidate();

    auto result = value.apply(tx::Set {"settings.enabled", std::string {"false"}}, 3);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().operation, 3U);
    EXPECT_EQ(result.error().code, "type_mismatch");
}

TEST(CfgTxCandidate, RejectsDuplicateRemovalBeforeMutation) {
    auto value = candidate();

    auto result = value.apply(
        tx::Remove {"address_objects", {"existing", "existing"}}, 4);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, "duplicate_entry");
    EXPECT_TRUE(value.config().lookup("address_objects").exists("existing"));
}

TEST(CfgTxCandidate, ReportsOperationIndexAndPath) {
    auto value = candidate();

    auto result = value.apply(tx::Set {"missing.parent.value", std::string {"value"}}, 7);

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().operation, 7U);
    EXPECT_EQ(result.error().code, "unknown_path");
    EXPECT_EQ(result.error().path, "missing.parent.value");
}

TEST(CfgTxCandidate, SerializesAndReparsesCompleteCandidate) {
    auto value = candidate();
    ASSERT_TRUE(value.apply(tx::Set {"settings.workers", std::int64_t {4}}, 0));

    auto snapshot = value.snapshot();

    ASSERT_TRUE(snapshot);
    auto reloaded = tx::Candidate::load(*snapshot);
    ASSERT_TRUE(reloaded);
    EXPECT_EQ(static_cast<int>(reloaded->config().lookup("settings.workers")), 4);
}
