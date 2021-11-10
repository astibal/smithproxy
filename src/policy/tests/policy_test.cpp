#include <tcpcom.hpp>

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
