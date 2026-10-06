#include <gtest/gtest.h>

#include <service/httpd/httpd.hpp>

namespace {

using sx::webserver::HttpSessions;
using sx::webserver::TimedOptional;

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

} // namespace
