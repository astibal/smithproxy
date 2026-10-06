#include <gtest/gtest.h>

#include <proxy/explicitproxycx.hpp>

TEST(ExplicitProxyDnsState, RejectsEveryNonpositiveRequestDescriptor) {
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(-3));
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(-2));
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(-1));
    EXPECT_FALSE(sx::explicit_proxy::valid_dns_socket(0));
    EXPECT_TRUE(sx::explicit_proxy::valid_dns_socket(1));
}

TEST(ExplicitProxyDnsState, RetriesOnlyUntestedAddressFamilies) {
    EXPECT_FALSE(sx::explicit_proxy::next_dns_retry(false, false, false));
    EXPECT_EQ(sx::explicit_proxy::next_dns_retry(true, false, false), AAAA);
    EXPECT_EQ(sx::explicit_proxy::next_dns_retry(true, false, true), A);
    EXPECT_EQ(sx::explicit_proxy::next_dns_retry(true, true, false), AAAA);
    EXPECT_FALSE(sx::explicit_proxy::next_dns_retry(true, true, true));
}
