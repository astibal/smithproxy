#include <gtest/gtest.h>

#include <service/httpd/cfg/save.hpp>

#include <string>

namespace api = sx::webserver::cfg_save_api;
using nlohmann::json;

TEST(CfgSaveJson, DecodesExpectedRevision) {
    auto result = api::decode_request({
        {"params", {{"expected_revision", "0123456789abcdef"}}},
    });

    ASSERT_TRUE(result);
    EXPECT_EQ(result->expected_revision, "0123456789abcdef");
}

TEST(CfgSaveJson, RequiresParamsObject) {
    for(auto const& request : {
            json::array(),
            json::object(),
            json {{"params", nullptr}},
        }) {
        auto result = api::decode_request(request);

        ASSERT_FALSE(result);
        EXPECT_EQ(result.error().code, "invalid_request");
    }
}

TEST(CfgSaveJson, RequiresBoundedRevisionString) {
    for(auto const& [request, code] : {
            std::pair {
                json {{"params", json::object()}},
                "missing_expected_revision",
            },
            std::pair {
                json {{"params", {{"expected_revision", nullptr}}}},
                "invalid_expected_revision",
            },
            std::pair {
                json {{"params", {{"expected_revision", ""}}}},
                "invalid_expected_revision",
            },
            std::pair {
                json {{"params", {{"expected_revision", std::string(129, 'a')}}}},
                "invalid_expected_revision",
            },
        }) {
        auto result = api::decode_request(request);

        ASSERT_FALSE(result);
        EXPECT_EQ(result.error().code, code);
    }
}
