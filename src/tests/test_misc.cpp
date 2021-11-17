#include <gtest/gtest.h>

#include <utils/tenants.hpp>

TEST(SxMain, TenantConfig) {

    using namespace sx::cfg;

    std::string l1 = " 0 ; default ; 0.0.0.0/0 ;  ::/0";
    std::string l2 = "# 1 ; first ; 1.1.1.1/24 ;     ";
    std::string l3 = "2 ; second ; 2.2.2.2/24 ;";
    std::string l4 = " 3; third;;3:3:3::0/64";

    std::vector<TenantConfig> ret1;
    process_tenant_config_line(l1, ret1);
    process_tenant_config_line(l2, ret1);
    process_tenant_config_line(l3, ret1);
    process_tenant_config_line(l4, ret1);

    std::for_each(ret1.begin(), ret1.end(), [](auto& x) { std::cout << x.to_string() << std::endl; });

    ASSERT_TRUE(ret1.size() == 3);
    ASSERT_TRUE(ret1[0].index == 0);
    ASSERT_TRUE(ret1[0].name == "default");
    ASSERT_TRUE(ret1[0].ipv4 == "0.0.0.0/0");
    ASSERT_TRUE(ret1[0].ipv6 == "::/0");

    ASSERT_TRUE(ret1[1].index == 2);
    ASSERT_TRUE(ret1[1].name == "second");
    ASSERT_TRUE(ret1[1].ipv4 == "2.2.2.2/24");
    ASSERT_TRUE(ret1[1].ipv6 == "");

    ASSERT_TRUE(ret1[2].index == 3);
    ASSERT_TRUE(ret1[2].name == "third");
    ASSERT_TRUE(ret1[2].ipv4 == "");
    ASSERT_TRUE(ret1[2].ipv6 == "3:3:3::0/64");

    ASSERT_TRUE(find_tenant(ret1, "default").value_or(-1) == 0);
    ASSERT_TRUE(not find_tenant(ret1, "some"));
    ASSERT_TRUE(find_tenant(ret1, 3).value_or("") == "third");
    ASSERT_TRUE(not find_tenant(ret1, 5));
}