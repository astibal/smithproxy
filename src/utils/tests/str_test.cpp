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


TEST(sx_str_cli, mask_array) {
    std::string sample = "policy.[0]";
    ASSERT_TRUE(sx::str::cli::mask_array_index(sample) == "policy.[x]");
}

TEST(sx_str_cli, mask_parent) {
    std::string sample = "proto_objects.abc.id";
    ASSERT_TRUE(sx::str::cli::mask_parent(sample) == "proto_objects.[x].id");
}

TEST(sx_str_cli, mask_this) {
    std::string sample = "proto_objects.abc";
    ASSERT_TRUE(sx::str::cli::mask_this(sample) == "proto_objects.[x]");
}