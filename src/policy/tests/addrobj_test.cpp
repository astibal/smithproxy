#include <policy/addrobj.cpp>
#include <log/logan.hpp>

#include <gtest/gtest.h>

using namespace cidr;

TEST(CidrAddressTest, ZeroZeroMatchesAll) {
    auto all = CidrAddress(cidr_from_str("0.0.0.0/0"));
    CidrAddress::unique_cidr ip4_min(cidr_from_str("1.0.0.1"));
    ASSERT_EQ(all.contains(ip4_min.get()), 0);
}


TEST(CidrAddressTest, NonsenseInput) {
    auto garbage = CidrAddress(cidr_from_str("this is not an address"));
    ASSERT_TRUE(garbage.cidr() == nullptr);
    EXPECT_FALSE(garbage.match(nullptr));
    EXPECT_TRUE(garbage.ip().empty());
    EXPECT_EQ(garbage.to_string(iINF), "Cidr: invalid");
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
    CidrAddress::unique_cidr a(cidr_from_str("1.1.1.1"));
    auto const* host = cidr_numhost(a.get());
    ASSERT_NE(host, nullptr);
    EXPECT_EQ(std::string(host), "1");
}

TEST(CidrAddressTest, MatchesOnlyAddressesInsideNetwork) {
    CidrAddress network("192.0.2.0/24");
    CidrAddress::unique_cidr inside(cidr_from_str("192.0.2.42"));
    CidrAddress::unique_cidr outside(cidr_from_str("198.51.100.1"));
    CidrAddress::unique_cidr ipv6(cidr_from_str("2001:db8::1"));

    EXPECT_TRUE(network.match(inside.get()));
    EXPECT_FALSE(network.match(outside.get()));
    EXPECT_FALSE(network.match(ipv6.get()));
    EXPECT_EQ(network.ip(), "192.0.2.0");
    network.element_name() = "documentation-net";
    EXPECT_NE(network.to_string(iDEB).find("name=documentation-net"), std::string::npos);
}

TEST(FqdnAddressTest, MissingOrInvalidLookupFailsClosed) {
    DNS::get_dns_cache().clear();
    FqdnAddress address("x.test");
    CidrAddress::unique_cidr ip4(cidr_from_str("192.0.2.1"));

    EXPECT_FALSE(address.match(nullptr));
    EXPECT_FALSE(address.match(ip4.get()));
    EXPECT_EQ(address.find_dns_response(CIDR_IPV4), nullptr);
    EXPECT_EQ(address.find_dns_response(CIDR_IPV6), nullptr);
    EXPECT_EQ(address.find_dns_response(12345), nullptr);
    EXPECT_EQ(address.to_string(iINF), "Fqdn: x.test");
    EXPECT_NE(address.to_string(iDEB).find("not cached"), std::string::npos);
}

TEST(FqdnAddressTest, MatchesCachedAddressAnswers) {
    const unsigned char response_bytes[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 'x', 0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        192, 0, 2, 1
    };
    buffer packet(const_cast<unsigned char*>(response_bytes), sizeof(response_bytes),
                  sizeof(response_bytes), false);
    auto response = std::make_shared<DNS_Response>();
    ASSERT_TRUE(response->load(&packet).has_value());
    DNS::get_dns_cache().set("A:x.test", response);

    FqdnAddress address("x.test");
    CidrAddress::unique_cidr matching(cidr_from_str("192.0.2.1"));
    CidrAddress::unique_cidr different(cidr_from_str("192.0.2.2"));
    ASSERT_NE(matching, nullptr);
    ASSERT_NE(different, nullptr);

    EXPECT_TRUE(address.match(matching.get()));
    EXPECT_FALSE(address.match(different.get()));
    EXPECT_EQ(address.find_dns_response(CIDR_IPV4), response);
    EXPECT_NE(address.to_string(iDEB).find("cached A"), std::string::npos);

    DNS::get_dns_cache().clear();
}
