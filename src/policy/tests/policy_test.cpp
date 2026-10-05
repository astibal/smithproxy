#include <tcpcom.hpp>
#include <udpcom.hpp>

#include <policy/policy.hpp>
#include <log/logan.hpp>

#include <gtest/gtest.h>

using namespace cidr;

TEST(PolicyTest, match_addrgrp_cx) {
    PolicyRule p;
    auto h = baseHostCX(new TCPCom(), "192.168.1.1", "80");

    PolicyRule::group_of_addresses g;

    // matching range
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.1.0/24")));
    ASSERT_TRUE(p.match_addrgrp_cx(g, &h));

    // empty should return true
    g.clear();
    ASSERT_TRUE(p.match_addrgrp_cx(g, &h));

    // different subnet must return false
    g.clear();
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.11.0/24")));
    ASSERT_FALSE(p.match_addrgrp_cx(g, &h));

    // two ranges one should match
    g.clear();
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.11.0/24")));
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.1.0/24")));
    ASSERT_TRUE(p.match_addrgrp_cx(g, &h));


    // two ranges NONE should match
    g.clear();
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.11.0/24")));
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.21.0/24")));
    ASSERT_FALSE(p.match_addrgrp_cx(g, &h));
}


TEST(PolicyTest, match_rangevec_cx) {
    PolicyRule p;
    auto h = baseHostCX(new TCPCom(), "192.168.1.1", "80");

    PolicyRule::group_of_ports g;

    // matching range
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(80,80)));
    ASSERT_TRUE(p.match_rangegrp_cx(g, &h));

    // empty should return true
    g.clear();
    ASSERT_TRUE(p.match_rangegrp_cx(g, &h));

    // different subnet must return false
    g.clear();
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(443,443)));
    ASSERT_FALSE(p.match_rangegrp_cx(g, &h));

    // two ranges one should match
    g.clear();
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(443,443)));
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(0,65535)));
    ASSERT_TRUE(p.match_rangegrp_cx(g, &h));


    // two ranges NONE should match
    g.clear();
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(443,443)));
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(143,143)));
    ASSERT_FALSE(p.match_rangegrp_cx(g, &h));
}

TEST(PolicyTest, ExplicitFirstRuleIsNeverRematchedDuringApplication) {
    unsigned matcher_calls = 0;
    auto matcher = [&] {
        ++matcher_calls;
        return 7;
    };

    EXPECT_EQ(sx::policy::preserve_explicit_match(0, matcher), 0);
    EXPECT_EQ(matcher_calls, 0U);
    EXPECT_EQ(sx::policy::preserve_explicit_match(3, matcher), 3);
    EXPECT_EQ(matcher_calls, 0U);
    EXPECT_EQ(sx::policy::preserve_explicit_match(-1, matcher), 7);
    EXPECT_EQ(matcher_calls, 1U);
}

TEST(PolicyTest, DirectMatchRequiresCompleteNonNullEndpointSets) {
    PolicyRule rule;
    baseHostCX left(new TCPCom(), "192.0.2.10", "12345");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    std::vector<baseHostCX*> empty;
    std::vector<baseHostCX*> lefts{&left};
    std::vector<baseHostCX*> rights{&right};

    EXPECT_FALSE(rule.match(empty, rights));
    EXPECT_FALSE(rule.match(lefts, empty));
    lefts.push_back(nullptr);
    EXPECT_FALSE(rule.match(lefts, rights));
}

TEST(PolicyTest, EveryEndpointMustMatchAddressAndPortOnTheSameFlowSet) {
    PolicyRule rule;
    rule.src.push_back(std::make_shared<CfgAddress>(
        std::make_shared<CidrAddress>("192.0.2.10/32")));
    rule.src_ports.push_back(std::make_shared<CfgRange>(
        std::pair<int, int>(2000, 2000)));

    baseHostCX address_only(new TCPCom(), "192.0.2.10", "1000");
    baseHostCX port_only(new TCPCom(), "192.0.2.11", "2000");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    std::vector<baseHostCX*> lefts{&address_only, &port_only};
    std::vector<baseHostCX*> rights{&right};

    // The address used to match the first endpoint and the port the second,
    // incorrectly authorizing the whole set although no endpoint matched the
    // complete source predicate.
    EXPECT_FALSE(rule.match(lefts, rights));

    address_only.port("2000");
    lefts.resize(1);
    EXPECT_TRUE(rule.match(lefts, rights));
}

TEST(PolicyTest, ProtocolAndMalformedEndpointFailuresAreFailClosed) {
    PolicyRule rule;
    rule.proto = std::make_shared<CfgUint8>(6);
    baseHostCX tcp(new TCPCom(), "192.0.2.10", "1000");
    baseHostCX udp(new UDPCom(), "198.51.100.20", "53");
    std::vector<baseHostCX*> lefts{&tcp};
    std::vector<baseHostCX*> rights{&udp};

    EXPECT_FALSE(rule.match(lefts, rights));

    rule.proto = std::make_shared<CfgUint8>(0);
    rule.src.push_back(std::make_shared<CfgAddress>(
        std::make_shared<CidrAddress>("192.0.2.0/24")));
    tcp.host("not-an-ip-address");
    EXPECT_NO_THROW(EXPECT_FALSE(rule.match(lefts, rights)));
    tcp.host("192.0.2.10");
    tcp.port("invalid");
    rule.src_ports.push_back(std::make_shared<CfgRange>(
        std::pair<int, int>(1, 65535)));
    EXPECT_FALSE(rule.match(lefts, rights));
}

TEST(PolicyTest, UserDisabledRulesSkipButConfigurationErrorsStopSelection) {
    PolicyRule rule;
    baseHostCX left(new TCPCom(), "192.0.2.10", "1000");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    std::vector<baseHostCX*> lefts{&left};
    std::vector<baseHostCX*> rights{&right};

    rule.is_disabled = true;
    EXPECT_FALSE(rule.match(lefts, rights));
    rule.is_disabled = false;
    rule.cfg_err_is_disabled = true;
    EXPECT_TRUE(rule.match(lefts, rights));
    rule.cfg_err_is_disabled = false;
    rule.cfg_err_is_degraded = true;
    EXPECT_TRUE(rule.match(lefts, rights));
}
