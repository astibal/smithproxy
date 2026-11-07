#include <gtest/gtest.h>

#include <service/cfgapi/cfg_revision.hpp>

#include <cstdint>
#include <string>

namespace {

class FakeRevData {
public:
    std::string next_id() {
        return "revision-" + std::to_string(++id_);
    }

    std::int64_t next_timestamp() {
        return ++timestamp_;
    }

private:
    unsigned int id_ {0};
    std::int64_t timestamp_ {1000};
};

sx::cfg::CfgRevHistory history_with(
    std::size_t capacity,
    FakeRevData& data) {
    return sx::cfg::CfgRevHistory(
        capacity,
        [&data]() { return data.next_id(); },
        [&data]() { return data.next_timestamp(); });
}

TEST(CfgRevHistory, StoresCompleteRevisionMetadata) {
    FakeRevData data;
    auto history = history_with(100, data);

    auto const revision = history.append("settings = {};", "cli", "set settings.flag true");

    EXPECT_EQ(revision.id, "revision-1");
    EXPECT_TRUE(revision.parent_id.empty());
    EXPECT_EQ(revision.timestamp_us, 1001);
    EXPECT_EQ(revision.source, "cli");
    EXPECT_EQ(revision.description, "set settings.flag true");
    EXPECT_EQ(revision.snapshot, "settings = {};");
    EXPECT_EQ(revision.content_hash.size(), 71U);
    EXPECT_EQ(revision.content_hash.substr(0, 7), "sha256:");
}

TEST(CfgRevHistory, EvictsOnlyTheOldestRevisionAtCapacity) {
    FakeRevData data;
    auto history = history_with(3, data);

    for(int index = 1; index <= 4; ++index) {
        history.append("snapshot-" + std::to_string(index), "test", "append");
    }

    ASSERT_EQ(history.size(), 3U);
    EXPECT_FALSE(history.find("revision-1"));
    EXPECT_TRUE(history.find("revision-2"));
    EXPECT_TRUE(history.find("revision-4"));
    auto const entries = history.entries();
    ASSERT_EQ(entries.size(), 3U);
    EXPECT_EQ(entries.front().id, "revision-2");
    EXPECT_EQ(entries.back().id, "revision-4");
}

TEST(CfgRevHistory, RepeatedContentGetsANewRevisionAndTheSameHash) {
    FakeRevData data;
    auto history = history_with(100, data);

    auto const first = history.append("same content", "cli", "initial");
    history.append("different content", "gui", "change");
    auto const restored = history.append(first.snapshot, "cli", "restore revision-1");

    EXPECT_NE(restored.id, first.id);
    EXPECT_EQ(restored.content_hash, first.content_hash);
    EXPECT_EQ(restored.parent_id, "revision-2");
}

TEST(CfgRevHistory, RejectsZeroCapacity) {
    EXPECT_THROW(sx::cfg::CfgRevHistory(0), std::invalid_argument);
}

TEST(CfgRevHistory, RetriesDuplicateGeneratedIds) {
    unsigned int call = 0;
    sx::cfg::CfgRevHistory history(
        100,
        [&call]() {
            ++call;
            return call < 3 ? "duplicate" : "unique";
        },
        []() { return 1; });

    history.append("one", "test", "first");
    auto const second = history.append("two", "test", "second");

    EXPECT_EQ(second.id, "unique");
}

}  // namespace
