#include <gtest/gtest.h>

#include <policy/profiles.hpp>

#include <tuple>

namespace {

TEST(ProfileContent, CompilesValidSessionFilterAndRejectsInvalidRegex) {
    ProfileContent profile;
    profile.rules_session_filter = R"(^client-[0-9]+$)";
    ASSERT_TRUE(profile.create_rule_session_filter_rx());
    ASSERT_TRUE(profile.rules_session_filter_rx.has_value());
    EXPECT_TRUE(std::regex_match("client-42", *profile.rules_session_filter_rx));

    profile.rules_session_filter = "([unterminated";
    EXPECT_FALSE(profile.create_rule_session_filter_rx());
    EXPECT_FALSE(profile.rules_session_filter_rx.has_value());
}

TEST(ProfileContentRule, ReplacementCadenceTriggersEveryNthCall) {
    ProfileContentRule rule;
    rule.replace_each_nth = 3;

    EXPECT_FALSE(rule.replacement_due());
    EXPECT_FALSE(rule.replacement_due());
    EXPECT_TRUE(rule.replacement_due());
    EXPECT_FALSE(rule.replacement_due());
    EXPECT_FALSE(rule.replacement_due());
    EXPECT_TRUE(rule.replacement_due());
}

TEST(ProfileContentRule, ZeroOneAndInvalidNegativeCadenceReplaceEveryCall) {
    for (int cadence : {0, 1, -1}) {
        ProfileContentRule rule;
        rule.replace_each_nth = cadence;
        EXPECT_TRUE(rule.replacement_due());
        EXPECT_TRUE(rule.replacement_due());
    }
}

TEST(ContentCaptureFormat, RoundTripsNamesExtensionsAndSuffixes) {
    using type = ContentCaptureFormat::type_t;
    for (auto const& [value, name, extension] : {
             std::tuple{type::SMCAP, "smcap", "smcap"},
             std::tuple{type::PCAP, "pcap", "pcapng"},
             std::tuple{type::PCAP_SINGLE, "pcap_single", "pcapng"},
         }) {
        ContentCaptureFormat format(value);
        EXPECT_EQ(format.to_str(), name);
        EXPECT_EQ(format.to_ext(), extension);
        EXPECT_EQ(format.to_ext("capture"), std::string("capture.") + extension);
        EXPECT_EQ(ContentCaptureFormat::from_str(name), value);
    }

    EXPECT_EQ(ContentCaptureFormat("unknown").value, type::SMCAP);
}

} // namespace
