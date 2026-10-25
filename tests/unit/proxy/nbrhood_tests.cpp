#include <gtest/gtest.h>

#include <proxy/nbrhood.hpp>

TEST(NeighborPersistence, StatsEntryRejectsMalformedInputTransactionally) {
    Neighbor::stats_entry_t entry;
    entry.days_epoch = 123;
    entry.counter = 7;
    entry.bytes_up = 11;
    entry.labels.insert("stable");

    EXPECT_FALSE(entry.ser_json_in({{"days_epoch", 456}, {"counter", "invalid"}}));
    EXPECT_EQ(entry.days_epoch, 123);
    EXPECT_EQ(entry.counter, 7U);
    EXPECT_EQ(entry.bytes_up, 11U);
    EXPECT_EQ(entry.labels, (std::set<std::string>{"stable"}));
}

TEST(NeighborPersistence, NeighborRejectsPartialStateAndBoundsHistory) {
    Neighbor neighbor("original.test");
    neighbor.tags_update("+stable");
    neighbor.timetable.push_back({});
    auto const before = neighbor.ser_json_out();

    auto malformed = before;
    malformed["hostname"] = "replacement.test";
    malformed["stats"][0]["counter"] = "invalid";
    EXPECT_FALSE(neighbor.ser_json_in(malformed));
    EXPECT_EQ(neighbor.ser_json_out(), before);

    auto valid = before;
    valid["hostname"] = "replacement.test";
    valid["stats"] = nlohmann::json::array();
    for (std::size_t i = 0; i < Neighbor::max_timetable_sz + 10; ++i) {
        valid["stats"].push_back({{"days_epoch", static_cast<time_t>(i)},
                                  {"counter", 1}});
    }
    EXPECT_TRUE(neighbor.ser_json_in(valid));
    EXPECT_EQ(neighbor.hostname, "replacement.test");
    EXPECT_EQ(neighbor.timetable.size(), Neighbor::max_timetable_sz);
}

TEST(NeighborPersistence, HoodSkipsInvalidEntriesAndUsesArrayResults) {
    NbrHood hood(4);
    EXPECT_EQ(hood.to_json(), nlohmann::json::array());
    EXPECT_EQ(hood.ser_json_out(), nlohmann::json::array());

    auto valid = Neighbor("valid.test").ser_json_out();
    nlohmann::json input = nlohmann::json::array({
        valid,
        {{"hostname", ""}, {"last_seen", 0}, {"stats", nlohmann::json::array()}},
        {{"hostname", "broken.test"}, {"last_seen", "bad"},
         {"stats", nlohmann::json::array()}}
    });
    hood.ser_json_in(input);

    EXPECT_TRUE(hood.cache().get("valid.test").has_value());
    EXPECT_FALSE(hood.cache().get("").has_value());
    EXPECT_FALSE(hood.cache().get("broken.test").has_value());
    ASSERT_TRUE(hood.to_json().is_array());
    EXPECT_EQ(hood.to_json().size(), 1U);
}
