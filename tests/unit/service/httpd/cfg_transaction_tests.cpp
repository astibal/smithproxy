#include <gtest/gtest.h>

#include <service/httpd/cfg/transaction.hpp>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace tx = sx::cfg::tx;
namespace api = sx::webserver::cfg_tx_api;
using nlohmann::json;

TEST(CfgTransactionJson, DecodesEveryOperationWithExplicitValueTypes) {
    const json request = json::array({
        {
            {"op", "set"},
            {"path", "settings.enabled"},
            {"value", {{"type", "bool"}, {"data", false}}},
        },
        {
            {"op", "set"},
            {"path", "settings.nameservers"},
            {"value", {{"type", "string_array"}, {"data", json::array()}}},
        },
        {{"op", "add"}, {"path", "address_objects"}, {"name", "office"}},
        {{"op", "remove"}, {"path", "policy"}, {"entries", {"0", "2"}}},
        {
            {"op", "move"},
            {"path", "policy"},
            {"source", 3},
            {"position", "before"},
            {"target", 1},
        },
    });

    auto operations = api::decode_operations(request);

    ASSERT_TRUE(operations);
    ASSERT_EQ(operations->size(), 5U);
    EXPECT_FALSE(std::get<bool>(std::get<tx::Set>((*operations)[0]).value));
    EXPECT_TRUE(std::get<std::vector<std::string>>(
                    std::get<tx::Set>((*operations)[1]).value).empty());
    EXPECT_EQ(std::get<tx::Add>((*operations)[2]).name, "office");
    EXPECT_EQ(std::get<tx::Remove>((*operations)[3]).entries,
              (std::vector<std::string> {"0", "2"}));
    const auto& move = std::get<tx::Move>((*operations)[4]);
    EXPECT_EQ(move.source, 3U);
    EXPECT_EQ(move.position, tx::Position::before);
    EXPECT_EQ(move.target, 1U);
}

TEST(CfgTransactionJson, RejectsAmbiguousOrMismatchedValues) {
    auto missing_type = api::decode_operations(json::array({
        {
            {"op", "set"},
            {"path", "settings.enabled"},
            {"value", {{"data", false}}},
        },
    }));
    ASSERT_FALSE(missing_type);
    EXPECT_EQ(missing_type.error().code, "missing_field");
    EXPECT_EQ(missing_type.error().operation, 0U);

    auto wrong_data = api::decode_operations(json::array({
        {
            {"op", "set"},
            {"path", "settings.enabled"},
            {"value", {{"type", "bool"}, {"data", "false"}}},
        },
    }));
    ASSERT_FALSE(wrong_data);
    EXPECT_EQ(wrong_data.error().code, "invalid_value");
}

TEST(CfgTransactionJson, ReportsOperationIndexAndPath) {
    auto result = api::decode_operations(json::array({
        {{"op", "add"}, {"path", "address_objects"}, {"name", "office"}},
        {
            {"op", "move"},
            {"path", "policy"},
            {"source", 0},
            {"position", "middle"},
            {"target", 1},
        },
    }));

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().operation, 1U);
    EXPECT_EQ(result.error().path, "policy");
    EXPECT_EQ(result.error().code, "invalid_position");
}

TEST(CfgTransactionJson, RejectsEmptyOperationList) {
    auto result = api::decode_operations(json::array());

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().operation, tx::Issue::no_operation);
    EXPECT_EQ(result.error().code, "invalid_operations");
}
