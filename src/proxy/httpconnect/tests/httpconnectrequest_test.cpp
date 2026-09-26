#include <gtest/gtest.h>

#include <proxy/httpconnect/httpconnectrequest.hpp>

TEST(HttpConnectRequest, ParsesFqdn) {
    auto const request = HttpConnectRequest::parse(
            "CONNECT example.test:443 HTTP/1.1\r\n");
    ASSERT_TRUE(request);
    EXPECT_EQ(request->host, "example.test");
    EXPECT_EQ(request->port, 443);
}

TEST(HttpConnectRequest, ParsesIpv4) {
    auto const request = HttpConnectRequest::parse(
            "CONNECT 127.0.0.1:8443 HTTP/1.0");
    ASSERT_TRUE(request);
    EXPECT_EQ(request->host, "127.0.0.1");
    EXPECT_EQ(request->port, 8443);
}

TEST(HttpConnectRequest, ParsesBracketedIpv6) {
    auto const request = HttpConnectRequest::parse(
            "CONNECT [2001:db8::1]:443 HTTP/1.1");
    ASSERT_TRUE(request);
    EXPECT_EQ(request->host, "2001:db8::1");
    EXPECT_EQ(request->port, 443);
}

TEST(HttpConnectRequest, RejectsNonConnectMethod) {
    EXPECT_FALSE(HttpConnectRequest::parse("GET example.test:443 HTTP/1.1"));
}

TEST(HttpConnectRequest, RejectsUnbracketedIpv6) {
    EXPECT_FALSE(HttpConnectRequest::parse("CONNECT 2001:db8::1:443 HTTP/1.1"));
}

TEST(HttpConnectRequest, RejectsMissingAndInvalidPorts) {
    EXPECT_FALSE(HttpConnectRequest::parse("CONNECT example.test HTTP/1.1"));
    EXPECT_FALSE(HttpConnectRequest::parse("CONNECT example.test:0 HTTP/1.1"));
    EXPECT_FALSE(HttpConnectRequest::parse("CONNECT example.test:65536 HTTP/1.1"));
    EXPECT_FALSE(HttpConnectRequest::parse("CONNECT example.test:https HTTP/1.1"));
}

TEST(HttpConnectRequest, RejectsUnsupportedHttpVersionAndTrailingData) {
    EXPECT_FALSE(HttpConnectRequest::parse("CONNECT example.test:443 HTTP/2"));
    EXPECT_FALSE(HttpConnectRequest::parse("CONNECT example.test:443 HTTP/1.1 extra"));
}
