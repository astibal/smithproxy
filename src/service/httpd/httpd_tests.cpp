#include <gtest/gtest.h>

#include <service/httpd/httpd.hpp>
#include <service/httpd/wh/webhook_lease.hpp>

namespace {

using sx::webserver::HttpSessions;
using sx::webserver::TimedOptional;
using sx::webserver::WebhookOverrideLease;

class HttpSessionsTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::extend_on_access = false;
    }

    void TearDown() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::extend_on_access = true;
    }
};

TEST_F(HttpSessionsTest, ExpiredValuesAreRejectedAndRemoved) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf"] = TimedOptional<std::string>("token", 0);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf"), "");
    HttpSessions::cleanup();

    auto lock = std::scoped_lock(HttpSessions::lock);
    EXPECT_TRUE(HttpSessions::access_keys.empty());
}

TEST_F(HttpSessionsTest, ValidValuesAndApiKeySnapshotsRoundTrip) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf_token"] = TimedOptional<std::string>("token", 60);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf_token"), "token");
    EXPECT_TRUE(HttpSessions::validate_tokens("auth", "token"));

    HttpSessions::replace_api_keys({"one", "two"});
    EXPECT_TRUE(HttpSessions::has_api_keys());
    EXPECT_TRUE(HttpSessions::has_api_key("one"));
    EXPECT_FALSE(HttpSessions::has_api_key("missing"));
    EXPECT_EQ(HttpSessions::api_keys_snapshot(),
              (std::set<std::string>{"one", "two"}));
}

TEST_F(HttpSessionsTest, InvalidCsrfDoesNotDestroyOtherwiseValidSession) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf_token"] = TimedOptional<std::string>("token", 60);
    }

    EXPECT_FALSE(HttpSessions::validate_tokens("auth", "wrong"));
    EXPECT_TRUE(HttpSessions::validate_tokens("auth", "token"));
}

TEST_F(HttpSessionsTest, GeneratedTokensAreNonEmptyAndIndependent) {
    auto const auth = HttpSessions::generate_auth_token();
    auto const csrf = HttpSessions::generate_csrf_token();

    EXPECT_EQ(auth.size(), 32U);
    EXPECT_EQ(csrf.size(), 32U);
    EXPECT_NE(auth, csrf);
}

TEST(WebhookOverrideLeaseTest, OwnerCanRenewAndAnotherOwnerCannotReplace) {
    WebhookOverrideLease lease;
    auto acquired = lease.acquire_or_renew("http://first", false, 60, {}, "owner-a", 1000);
    EXPECT_EQ(acquired.outcome, WebhookOverrideLease::Outcome::acquired);
    EXPECT_EQ(acquired.lease_id, "owner-a");
    EXPECT_EQ(acquired.expires_at, 1060);

    auto conflict = lease.acquire_or_renew("http://second", true, 60, {}, "owner-b", 1001);
    EXPECT_EQ(conflict.outcome, WebhookOverrideLease::Outcome::conflict);
    EXPECT_EQ(lease.target(1001).url, "http://first");

    auto renewed = lease.acquire_or_renew("http://renewed", true, 30, "owner-a", {}, 1020);
    EXPECT_EQ(renewed.outcome, WebhookOverrideLease::Outcome::renewed);
    EXPECT_EQ(renewed.expires_at, 1050);
    EXPECT_EQ(lease.target(1020).url, "http://renewed");
}

TEST(WebhookOverrideLeaseTest, ExpiryAllowsNewOwnerAndReleaseChecksOwnership) {
    WebhookOverrideLease lease;
    lease.acquire_or_renew("http://first", true, 10, {}, "owner-a", 1000);

    auto acquired = lease.acquire_or_renew("http://second", false, 999, {}, "owner-b", 1010);
    EXPECT_EQ(acquired.outcome, WebhookOverrideLease::Outcome::acquired);
    EXPECT_EQ(acquired.expires_at, 1310); // TTL is capped at five minutes.

    EXPECT_EQ(lease.release("owner-a", 1011).outcome, WebhookOverrideLease::Outcome::conflict);
    EXPECT_TRUE(lease.target(1011).active);
    EXPECT_EQ(lease.release("owner-b", 1011).outcome, WebhookOverrideLease::Outcome::released);
    EXPECT_FALSE(lease.target(1011).active);

    lease.acquire_or_renew("http://third", true, 10, {}, "owner-c", 2000);
    auto reacquired = lease.acquire_or_renew("http://fourth", true, 10, "owner-c", "owner-d", 2010);
    EXPECT_EQ(reacquired.outcome, WebhookOverrideLease::Outcome::acquired);
    EXPECT_EQ(reacquired.lease_id, "owner-d");
}

TEST(WebhookOverrideLeaseTest, RejectsIncompleteAcquisitionAndClampsShortTtl) {
    WebhookOverrideLease lease;
    EXPECT_EQ(lease.release("nobody", 1000).outcome, WebhookOverrideLease::Outcome::absent);
    EXPECT_EQ(lease.acquire_or_renew({}, true, 60, {}, "owner", 1000).outcome,
              WebhookOverrideLease::Outcome::invalid);
    EXPECT_EQ(lease.acquire_or_renew("http://first", true, 1, {}, "owner", 1000).expires_at,
              1010);
}

} // namespace
