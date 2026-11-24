#include <gtest/gtest.h>

#include <service/httpd/login_request.hpp>

TEST(LoginRequestTest, DecodesEscapedCredentialsAndEmbeddedEquals) {
    const auto result = sx::webserver::parse_login_request(
        "username=alice%40example.test&password=a%2Bb%3Dc%26d");

    ASSERT_TRUE(result.request);
    EXPECT_EQ(result.request->username, "alice@example.test");
    EXPECT_EQ(result.request->password, "a+b=c&d");
}

TEST(LoginRequestTest, ConvertsFormPlusToSpace) {
    const auto result = sx::webserver::parse_login_request(
        "username=alice&password=correct+horse");

    ASSERT_TRUE(result.request);
    EXPECT_EQ(result.request->password, "correct horse");
}

TEST(LoginRequestTest, RejectsMalformedDuplicateAndUnknownFields) {
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice&password=%Q0").request);
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice&username=bob&password=secret").request);
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice&password=secret&redirect=%2F").request);
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice").request);
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice&password=%00secret").request);
}

TEST(LoginRequestTest, RejectsUnsafeOrUnboundedCredentials) {
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=&password=secret").request);
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice%0Aforged&password=secret").request);
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice%1B%5B31m&password=secret").request);
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice&password=").request);

    const auto long_username = std::string(257U, 'a');
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=" + long_username + "&password=secret").request);
    const auto long_password = std::string(1025U, 'p');
    EXPECT_FALSE(sx::webserver::parse_login_request(
        "username=alice&password=" + long_password).request);
}
