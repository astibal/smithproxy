#include <gtest/gtest.h>

#include <proxy/explicitproxyport.hpp>

TEST(ExplicitProxySourcePort, AcceptsValidBoundaries) {
    EXPECT_EQ(sx::explicit_proxy::parse_source_port("1"), 1);
    EXPECT_EQ(sx::explicit_proxy::parse_source_port("443"), 443);
    EXPECT_EQ(sx::explicit_proxy::parse_source_port("65535"), 65535);
}

TEST(ExplicitProxySourcePort, RejectsMalformedAndOutOfRangeValues) {
    for(auto const value: {
            "", "http", "443x", " 443", "443 ", "+443", "-1",
            "0", "65536", "999999999999999999999999999999999999"}) {
        EXPECT_FALSE(sx::explicit_proxy::parse_source_port(value)) << value;
    }
}

TEST(ExplicitProxySourcePort, DoesNotAcceptNumericPrefix) {
    std::string value = "443";
    value.push_back('\0');
    value += "ignored";
    EXPECT_FALSE(sx::explicit_proxy::parse_source_port(value));
}
