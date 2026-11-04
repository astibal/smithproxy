#include <gtest/gtest.h>

#include <service/cfgapi/cfg_serialization.hpp>

#include <string>

TEST(CfgSerialization, ProducesStableSnapshotText) {
    libconfig::Config config;
    auto& root = config.getRoot();
    root.add("enabled", libconfig::Setting::TypeBoolean) = true;
    root.add("name", libconfig::Setting::TypeString) = "office";

    auto const first = cfgapi_detail::serialize_config(config);
    auto const second = cfgapi_detail::serialize_config(config);

    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    EXPECT_EQ(*first, *second);
    EXPECT_NE(first->find("enabled = true"), std::string::npos);
    EXPECT_NE(first->find("name = \"office\""), std::string::npos);
}

TEST(CfgSerialization, SnapshotChangesWithConfiguration) {
    libconfig::Config config;
    auto& value = config.getRoot().add("value", libconfig::Setting::TypeInt);
    value = 1;
    auto const before = cfgapi_detail::serialize_config(config);

    value = 2;
    auto const after = cfgapi_detail::serialize_config(config);

    ASSERT_TRUE(before);
    ASSERT_TRUE(after);
    EXPECT_NE(*before, *after);
}
