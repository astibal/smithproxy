#include <utils/str.cpp>

#include <gtest/gtest.h>


TEST(sx_str_replace, nothing_to_replace) {
    std::string orig = "this is a simple itch";

    std::string sample = orig;
    sx::str::string_replace_all(sample, "", "XXXXXXX");
    ASSERT_TRUE(sample == orig);
}

TEST(sx_str_replace, multiple_items) {
    std::string sample = "this is a simple itch";
    sx::str::string_replace_all(sample, "i", "X");
    ASSERT_TRUE(sample == "thXs Xs a sXmple Xtch");
}