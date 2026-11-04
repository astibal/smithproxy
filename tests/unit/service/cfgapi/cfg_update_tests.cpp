#include <gtest/gtest.h>

#include <service/cfgapi/cfg_update.hpp>

#include <memory>
#include <thread>
#include <vector>

TEST(UpdateBoard, NewSubscriberStartsAtCurrentState) {
    UpdateBoard board;
    board.upgrade("existing-writer");

    board.subscribe("cli-1");

    EXPECT_FALSE(board.differs("cli-1"));
    EXPECT_EQ(board.current_delta("cli-1"), 0);
}

TEST(UpdateBoard, SubscriberSeesAndAcknowledgesChanges) {
    UpdateBoard board;
    board.subscribe("cli-1");

    board.upgrade("cli-2");

    EXPECT_TRUE(board.differs_current("cli-1"));
    EXPECT_EQ(board.current_delta("cli-1"), 1);
    board.ack_current("cli-1");
    EXPECT_FALSE(board.differs_current("cli-1"));
}

TEST(UpdateBoard, PollsOneConsistentUpdateNotice) {
    UpdateBoard board;
    board.subscribe("cli-1");
    board.upgrade("cli-2");
    board.save("cli-2");

    auto const notice = board.poll_updates("cli-1");

    EXPECT_TRUE(notice.current_changed);
    EXPECT_TRUE(notice.saved_changed);
    EXPECT_EQ(notice.updater, "cli-2");
    EXPECT_FALSE(board.differs("cli-1"));
}

TEST(UpdateBoard, TracksRunningAndSavedRevisions) {
    UpdateBoard board;
    auto const initial = board.init_revision("setting = 1;", "startup");

    EXPECT_EQ(board.revision_current(), initial.id);
    EXPECT_EQ(board.revision_saved(), initial.id);
    EXPECT_FALSE(board.unsaved());

    auto const changed = board.upgrade("cli", "setting = 2;", "set setting 2");

    EXPECT_EQ(changed.parent_id, initial.id);
    EXPECT_EQ(board.revision_current(), changed.id);
    EXPECT_EQ(board.revision_saved(), initial.id);
    EXPECT_TRUE(board.unsaved());

    board.save("cli");
    EXPECT_EQ(board.revision_saved(), changed.id);
    EXPECT_FALSE(board.unsaved());
}

TEST(UpdateBoard, RevisionHistoryCanOnlyBeInitializedOnce) {
    UpdateBoard board;
    board.init_revision("setting = 1;", "startup");

    EXPECT_THROW(board.init_revision("setting = 2;", "startup"), std::logic_error);
}

TEST(UpdateBoard, SerializesConcurrentVersionUpdates) {
    UpdateBoard board;
    constexpr int thread_count = 4;
    constexpr int updates_per_thread = 250;
    std::vector<std::thread> writers;

    for(int thread = 0; thread < thread_count; ++thread) {
        writers.emplace_back([&board]() {
            for(int update = 0; update < updates_per_thread; ++update) {
                board.upgrade("concurrent-writer");
            }
        });
    }
    for(auto& writer : writers) {
        writer.join();
    }

    EXPECT_EQ(
        board.version_current(),
        UpdateBoard::starting_num + thread_count * updates_per_thread);
}

TEST(UpdateBoardSubscriber, SubscribesForItsLifetime) {
    auto board = std::make_shared<UpdateBoard>();
    {
        UpdateBoardSubscriber subscriber("cli-1", board);
        board->upgrade("cli-2");
        EXPECT_TRUE(board->differs("cli-1"));
    }

    // An unknown subscriber starts at the current state. This verifies that
    // the RAII subscription was removed when it left scope.
    EXPECT_FALSE(board->differs("cli-1"));
}
