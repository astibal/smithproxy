#include <gtest/gtest.h>

#include <service/cfgapi/cfgvalue.hpp>
#include <service/cfgapi/cfg_serialization.hpp>

#include <cstdlib>
#include <cstdio>
#include <string_view>

TEST(CfgValue, UnsignedFiltersRequireTheCompleteCanonicalNumber) {
    for (auto const* accepted : {"0", "1", "65535", "9223372036854775807"})
        EXPECT_TRUE(CfgValue::VALUE_UINT(accepted).accepted()) << accepted;

    for (auto const* rejected : {"", "-1", "+1", " 1", "1 ", "12x",
                                 "9223372036854775808"})
        EXPECT_FALSE(CfgValue::VALUE_UINT(rejected).accepted()) << rejected;

    EXPECT_FALSE(CfgValue::VALUE_UINT_NZ("0").accepted());
    EXPECT_TRUE(CfgValue::VALUE_UINT_NZ("1").accepted());
}

TEST(CfgValue, BooleanFilterNormalizesAcceptedSpellings) {
    EXPECT_EQ(CfgValue::VALUE_BOOL("YeS").get_value(), "true");
    EXPECT_EQ(CfgValue::VALUE_BOOL("f").get_value(), "false");
    EXPECT_FALSE(CfgValue::VALUE_BOOL("truthy").accepted());
}

TEST(CfgValue, CopyAssignmentPreservesValidationAndSuggestionPolicy) {
    CfgValue source("source");
    source.help("long").help_quick("short").may_be_empty(false)
          .value_filter(CfgValue::VALUE_UINT)
          .suggestion_generator(CfgValue::SUGGESTION_BOOL);

    CfgValue copy("copy");
    copy = source;
    EXPECT_EQ(copy.name(), "source");
    EXPECT_EQ(copy.help(), "long");
    EXPECT_EQ(copy.help_quick(), "short");
    EXPECT_FALSE(copy.may_be_empty());
    EXPECT_EQ(copy.suggestion_generate("", ""),
              (std::vector<std::string>{"true", "false"}));
    ASSERT_EQ(copy.value_filter().size(), 2U);
    EXPECT_FALSE(copy.value_filter().back()("12x").accepted());
}

TEST(CfgFactorySerialization, LargeConfigurationCannotBlockOnPipeCapacity) {
    libconfig::Config config;
    auto& entries = config.getRoot().add("entries", libconfig::Setting::TypeList);
    std::string const value(256, 'x');
    for(int i = 0; i < 8192; ++i)
        entries.add(libconfig::Setting::TypeString) = value;

    char* output = nullptr;
    std::size_t output_size = 0;
    FILE* destination = open_memstream(&output, &output_size);
    ASSERT_NE(destination, nullptr);
    ASSERT_EQ(cfgapi_detail::write_config_crlf(config, destination), 0);
    ASSERT_EQ(fclose(destination), 0);

    ASSERT_GT(output_size, 2U * 1024U * 1024U);
    std::string_view serialized(output, output_size);
    for(std::size_t newline = serialized.find('\n'); newline != std::string_view::npos;
        newline = serialized.find('\n', newline + 1)) {
        ASSERT_GT(newline, 0U);
        EXPECT_EQ(serialized[newline - 1], '\r');
    }
    free(output);
}
