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

TEST(HttpConnectRequest, AcceptsPortBoundariesAndHttpVersions) {
    for(auto const line: {
            "CONNECT example.test:1 HTTP/1.0",
            "CONNECT example.test:65535 HTTP/1.1",
            "CONNECT [::1]:1 HTTP/1.0\r\n",
            "CONNECT [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535 HTTP/1.1"}) {
        EXPECT_TRUE(HttpConnectRequest::parse(line)) << line;
    }
}

TEST(HttpConnectRequest, RejectsMalformedRequestLineFraming) {
    for(auto const line: {
            "", "CONNECT", "CONNECT ",
            "connect example.test:443 HTTP/1.1",
            "CONNECT  example.test:443 HTTP/1.1",
            "CONNECT\texample.test:443 HTTP/1.1",
            "CONNECT example.test:443\tHTTP/1.1",
            "CONNECT example.test:443 HTTP/1.1\n",
            "CONNECT example.test:443 HTTP/1.1\r",
            "CONNECT example.test:443 HTTP/1.1\r\nextra"}) {
        EXPECT_FALSE(HttpConnectRequest::parse(line)) << line;
    }
}

TEST(HttpConnectRequest, RejectsMalformedAuthorities) {
    for(auto const line: {
            "CONNECT :443 HTTP/1.1",
            "CONNECT example.test: HTTP/1.1",
            "CONNECT example.test:+443 HTTP/1.1",
            "CONNECT example.test:-1 HTTP/1.1",
            "CONNECT example.test:443x HTTP/1.1",
            "CONNECT [::1]443 HTTP/1.1",
            "CONNECT [::1 HTTP/1.1",
            "CONNECT []:443 HTTP/1.1",
            "CONNECT [::1]:443:80 HTTP/1.1",
            "CONNECT example.test:443:80 HTTP/1.1"}) {
        EXPECT_FALSE(HttpConnectRequest::parse(line)) << line;
    }
}

TEST(HttpConnectRequest, DoesNotTruncateEmbeddedNul) {
    std::string line = "CONNECT example.test:443 HTTP/1.1";
    line.push_back('\0');
    line += "ignored";
    EXPECT_FALSE(HttpConnectRequest::parse(line));
}
