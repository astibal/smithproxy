#include <policy/addrobj.cpp>
#include <log/logan.hpp>

#include <gtest/gtest.h>

using namespace cidr;

TEST(CidrAddressTest, ZeroZeroMatchesAll) {
    auto all = CidrAddress(cidr_from_str("0.0.0.0/0"));
    auto ip4_min = cidr_from_str("1.0.0.1");
    ASSERT_TRUE(all.contains(ip4_min) == 0);
}


TEST(CidrAddressTest, NonsenseInput) {
    auto garbage = CidrAddress(cidr_from_str("this is not an address"));
    ASSERT_TRUE(garbage.cidr() == nullptr);
}

TEST(CidrAddressTest, NonsenseInput2) {
    auto garbage = CidrAddress(cidr_from_str("this.is.a.4"));
    ASSERT_TRUE(garbage.cidr() == nullptr);
}

TEST(CidrAddressTest, NonsenseInput3) {
    auto garbage = CidrAddress(cidr_from_str("this.is.a.4/23423"));
    ASSERT_TRUE(garbage.cidr() == nullptr);
}

TEST(CidrAddressTest, Host_HostTest) {
    auto a = cidr_from_str("1.1.1.1");
    ASSERT_TRUE(std::string(cidr_numhost(a)) == "1");
}