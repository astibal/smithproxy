#include <gtest/gtest.h>

#include <service/admin/admin_config.hpp>
#include <utils/crypto.hpp>

namespace {

std::string verifier(std::string_view password = "test password") {
    auto result = sx::crypto::password_verifier(password);
    if(!result) throw std::runtime_error("cannot create test password verifier");
    return std::move(*result);
}

} // namespace

TEST(AdminConfig, RoundTripsTypedAdministratorRecords) {
    sx::admin::Config config;
    const auto first_verifier = verifier("first password");
    const auto second_verifier = verifier("second password");
    config.upsert({"alice@example.test", true, first_verifier});
    config.upsert({"disabled-admin", false, second_verifier});

    const auto parsed = sx::admin::Config::parse(config.serialize());

    ASSERT_EQ(parsed.administrators().size(), 2U);
    EXPECT_EQ(parsed.administrators()[0],
              (sx::admin::Administrator{"alice@example.test", true, first_verifier}));
    EXPECT_EQ(parsed.administrators()[1],
              (sx::admin::Administrator{"disabled-admin", false, second_verifier}));
}

TEST(AdminConfig, UpdatesAndRemovesAdministratorsByStableName) {
    sx::admin::Config config;
    config.upsert({"admin", true, verifier("initial password")});
    const auto replacement = verifier("replacement password");

    config.upsert({"admin", false, replacement});

    ASSERT_EQ(config.administrators().size(), 1U);
    ASSERT_NE(config.find("admin"), nullptr);
    EXPECT_FALSE(config.find("admin")->enabled);
    EXPECT_EQ(config.find("admin")->password_verifier, replacement);
    EXPECT_TRUE(config.remove("admin"));
    EXPECT_FALSE(config.remove("admin"));
    EXPECT_EQ(config.find("admin"), nullptr);
}

TEST(AdminConfig, AuthenticatesEnabledAdministratorsWithoutLeakingUnknownNames) {
    sx::admin::Config config;
    config.upsert({"alice", true, verifier("correct password")});
    config.upsert({"disabled", false, verifier("disabled password")});

    EXPECT_EQ(config.authenticate("alice", "correct password"),
              sx::admin::AuthenticationStatus::authenticated);
    EXPECT_EQ(config.authenticate("alice", "wrong password"),
              sx::admin::AuthenticationStatus::denied);
    EXPECT_EQ(config.authenticate("disabled", "disabled password"),
              sx::admin::AuthenticationStatus::denied);
    EXPECT_EQ(config.authenticate("missing", "correct password"),
              sx::admin::AuthenticationStatus::not_configured);
}

TEST(AdminConfig, RejectsUnknownSchemaIncompleteRecordsAndDuplicateNames) {
    const auto password = verifier();
    EXPECT_THROW(sx::admin::Config::parse(R"(
        admin = { schema_version = 2; administrators = (); };
    )"), std::invalid_argument);
    EXPECT_THROW(sx::admin::Config::parse(R"(
        admin = { schema_version = 1; administrators = ({ name = "admin"; }); };
    )"), std::invalid_argument);
    EXPECT_THROW(sx::admin::Config::parse(
        "admin = { schema_version = 1; administrators = ("
        "{ name = \"admin\"; enabled = true; password_verifier = \"" + password + "\"; },"
        "{ name = \"admin\"; enabled = false; password_verifier = \"" + password + "\"; }"
        "); };"), std::invalid_argument);
    EXPECT_THROW(sx::admin::Config::parse(R"(
        admin = { schema_version = 1; administrators = (); unexpected = true; };
    )"), std::invalid_argument);
}

TEST(AdminConfig, RejectsInvalidNamesAndPasswordVerifiersBeforeSerialization) {
    sx::admin::Config config;

    EXPECT_THROW(config.upsert({"name with spaces", true, verifier()}), std::invalid_argument);
    EXPECT_THROW(config.upsert({u8"ádmin", true, verifier()}), std::invalid_argument);
    EXPECT_THROW(config.upsert({"admin", true, "plaintext"}), std::invalid_argument);
    EXPECT_TRUE(config.administrators().empty());
}
