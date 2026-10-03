#include <gtest/gtest.h>

#include <service/http/jsonize.hpp>

TEST(Jsonize, LoadsTypedParametersAndRejectsMissingOrMalformedValues) {
    auto const request = R"({"params":{"name":"alpha","count":42,"enabled":true}})";
    EXPECT_EQ(jsonize::load_json_params<std::string>(request, "name"), "alpha");
    EXPECT_EQ(jsonize::load_json_params<int>(request, "count"), 42);
    EXPECT_EQ(jsonize::load_json_params<bool>(request, "enabled"), true);
    EXPECT_FALSE(jsonize::load_json_params<int>(request, "missing").has_value());
    EXPECT_FALSE(jsonize::load_json_params<int>(request, "name").has_value());
    EXPECT_FALSE(jsonize::load_json_params<int>("not-json", "count").has_value());
}

TEST(Jsonize, StatusResponseUsesExactlyOneStableResultKey) {
    auto const success = jsonize::cfg_status_response({true, "stored"});
    EXPECT_EQ(success, nlohmann::json({{"success", "stored"}}));
    EXPECT_FALSE(success.contains("error"));

    auto const error = jsonize::cfg_status_response({false, "rejected"});
    EXPECT_EQ(error, nlohmann::json({{"error", "rejected"}}));
    EXPECT_FALSE(error.contains("success"));
}

TEST(Jsonize, ConvertsNestedLibconfigIncludingScalarLists) {
    libconfig::Config config;
    config.readString(R"(
        number = 42;
        large = 5000000000L;
        text = "hello";
        ratio = 1.5;
        enabled = true;
        array = [ 1, 2, 3 ];
        list = ( 7, "eight", false, { nested = "value"; } );
        group = { child = 9; };
    )");

    auto const converted = jsonize::from(config.getRoot());
    EXPECT_EQ(converted["number"], "42");
    EXPECT_EQ(converted["large"], "5000000000");
    EXPECT_EQ(converted["text"], "hello");
    EXPECT_EQ(converted["ratio"], "1.5");
    EXPECT_EQ(converted["enabled"], "1");
    EXPECT_EQ(converted["array"], nlohmann::json({"1", "2", "3"}));
    ASSERT_TRUE(converted["list"].is_array());
    EXPECT_EQ(converted["list"][0], "7");
    EXPECT_EQ(converted["list"][1], "eight");
    EXPECT_EQ(converted["list"][2], "0");
    EXPECT_EQ(converted["list"][3]["nested"], "value");
    EXPECT_EQ(converted["group"]["child"], "9");
}
