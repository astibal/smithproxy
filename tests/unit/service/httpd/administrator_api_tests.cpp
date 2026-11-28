#include <gtest/gtest.h>

#include <service/httpd/administrator_api.hpp>
#include <service/httpd/httpd.hpp>

namespace {

using nlohmann::json;
using sx::webserver::HttpSessions;

TEST(AdministratorApiRequestTest, DecodesCreateAndTransportCredentials) {
    const auto result = sx::webserver::parse_administrator_create_request({
        {"name", "security-admin"},
        {"password", "correct horse battery staple"},
        {HttpSessions::ATT_AUTH_TOKEN, "session"},
        {HttpSessions::ATT_CSRF_TOKEN, "csrf"},
    });

    ASSERT_TRUE(result.request);
    EXPECT_EQ(result.request->name, "security-admin");
    EXPECT_EQ(result.request->password, "correct horse battery staple");
}

TEST(AdministratorApiRequestTest, RejectsUnknownOrMistypedCreateFields) {
    EXPECT_FALSE(sx::webserver::parse_administrator_create_request({
        {"name", "admin"}, {"password", "secret"}, {"enabled", true},
    }).request);
    EXPECT_FALSE(sx::webserver::parse_administrator_create_request({
        {"name", 7}, {"password", "secret"},
    }).request);
    EXPECT_FALSE(sx::webserver::parse_administrator_create_request(
        json::array()).request);
}

TEST(AdministratorApiRequestTest, DecodesPasswordEnabledAndRemoveRequests) {
    const auto password = sx::webserver::parse_administrator_password_request({
        {"name", "admin"}, {"password", "replacement"},
    });
    const auto enabled = sx::webserver::parse_administrator_enabled_request({
        {"name", "admin"}, {"enabled", false},
    });
    const auto removed = sx::webserver::parse_administrator_remove_request({
        {"name", "admin"},
    });

    ASSERT_TRUE(password.request);
    EXPECT_EQ(password.request->password, "replacement");
    ASSERT_TRUE(enabled.request);
    EXPECT_FALSE(enabled.request->enabled);
    ASSERT_TRUE(removed.request);
    EXPECT_EQ(removed.request->name, "admin");
}

TEST(AdministratorApiRequestTest, RequiresExactChangeShapes) {
    EXPECT_FALSE(sx::webserver::parse_administrator_password_request({
        {"name", "admin"},
    }).request);
    EXPECT_FALSE(sx::webserver::parse_administrator_enabled_request({
        {"name", "admin"}, {"enabled", "false"},
    }).request);
    EXPECT_FALSE(sx::webserver::parse_administrator_remove_request({
        {"name", "admin"}, {"password", "unexpected"},
    }).request);
}

TEST(AdministratorApiRequestTest, DecodesEnrollmentWithoutAdministratorName) {
    const auto result = sx::webserver::parse_administrator_enrollment_request({
        {"enrollment_token", std::string(64, 'a')},
        {"password", "initial password"},
    });

    ASSERT_TRUE(result.request);
    EXPECT_EQ(result.request->enrollment_token, std::string(64, 'a'));
    EXPECT_EQ(result.request->password, "initial password");
    EXPECT_FALSE(sx::webserver::parse_administrator_enrollment_request({
        {"enrollment_token", std::string(64, 'a')},
        {"password", "initial password"},
        {"name", "attacker-selected-name"},
    }).request);
}

}  // namespace
