#include "../broker_client.hpp"
#include <gtest/gtest.h>

using namespace sx::auth;

TEST(AuthBasic, AcceptsBoundedCredentialsAndColonInPassword) {
    auto result = http_basic_credentials("CONNECT test:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYTpzcw==\r\n\r\n");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->username, "user");
    EXPECT_EQ(result->password, "pa:ss");
}

TEST(AuthBasic, RejectsMissingDuplicateMalformedAndFoldedCredentials) {
    const std::vector<std::string> cases{
        "", "Proxy-Authorization: Basic !!!=\r\n", "Proxy-Authorization: Basic dTpw====\r\n",
        "Proxy-Authorization: Basic dTpw\r\nProxy-Authorization: Basic dTpw\r\n",
        " Proxy-Authorization: Basic dTpw\r\n", "Proxy-Authorization: Bearer abc\r\n",
        "Proxy-Authorization: Basic dTpwdw=B\r\n", "Proxy-Authorization: Basic dTpwdx==\r\n",
    };
    for(const auto& headers : cases) {
        EXPECT_FALSE(http_basic_credentials("CONNECT test:443 HTTP/1.1\r\n" + headers + "\r\n"));
    }
}

TEST(AuthBroker, MissingSocketNeverAuthenticates) {
    BrokerPapBackend backend("/tmp/smithproxy-auth-nonexistent/test.sock", 100);
    auto result = backend.verify_pap({"user", "password"}, {});
    ASSERT_TRUE(result);
    EXPECT_EQ(result->status, Status::error);
    EXPECT_FALSE(static_cast<bool>(*result));
}

TEST(AuthBroker, RejectsInvalidSocketPaths) {
    EXPECT_THROW(BrokerPapBackend(""), std::invalid_argument);
    EXPECT_THROW(BrokerPapBackend("relative"), std::invalid_argument);
    EXPECT_THROW(BrokerPapBackend("/" + std::string(200, 'a')), std::invalid_argument);
}
