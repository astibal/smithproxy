#include <gtest/gtest.h>

#include <service/cfgapi/cfgvalue.hpp>

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
