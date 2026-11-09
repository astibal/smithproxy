#include <gtest/gtest.h>

#include <service/cfgapi/cfg_save.hpp>

#include <future>
#include <mutex>
#include <stdexcept>
#include <string>

namespace {

struct SaveFixture {
    UpdateBoard board;
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;

    SaveFixture() {
        board.init_revision("initial snapshot", "startup");
    }

    UpdateBoard::RevisionState make_unsaved() {
        board.upgrade("cli", "changed snapshot", "set settings.log_level");
        return board.revision_state();
    }

    sx::cfg::SaveResult save(
        std::string const& expected_revision,
        bool partial_config,
        sx::cfg::SaveFile save_file) {
        sx::cfg::CfgSaver saver({
            board,
            gate,
            config_mutex,
            partial_config,
            std::move(save_file),
        });
        return saver.save(expected_revision, "api:127.0.0.1");
    }
};

}  // namespace

TEST(CfgSave, RejectsAnActiveCommitLease) {
    SaveFixture fixture;
    auto const state = fixture.make_unsaved();
    ASSERT_TRUE(fixture.gate.acquire(
        state.current_id,
        "other-client",
        [&fixture] { return fixture.board.revision_current(); }));

    bool file_called = false;
    auto const result = fixture.save(state.current_id, false, [&file_called] {
        file_called = true;
        return true;
    });

    EXPECT_EQ(result.status, sx::cfg::SaveStatus::lease_busy);
    EXPECT_FALSE(file_called);
    EXPECT_TRUE(fixture.board.unsaved());
}

TEST(CfgSave, RejectsAStaleRunningRevision) {
    SaveFixture fixture;
    fixture.make_unsaved();
    bool file_called = false;

    auto const result = fixture.save("stale-revision", false, [&file_called] {
        file_called = true;
        return true;
    });

    EXPECT_EQ(result.status, sx::cfg::SaveStatus::stale_revision);
    EXPECT_FALSE(file_called);
    EXPECT_TRUE(result.revision.unsaved);
}

TEST(CfgSave, TreatsTheSavedRevisionAsIdempotent) {
    SaveFixture fixture;
    auto const state = fixture.board.revision_state();
    bool file_called = false;

    auto const result = fixture.save(state.current_id, false, [&file_called] {
        file_called = true;
        return true;
    });

    EXPECT_EQ(result.status, sx::cfg::SaveStatus::unchanged);
    EXPECT_TRUE(result.ok());
    EXPECT_FALSE(result.changed());
    EXPECT_FALSE(file_called);
    EXPECT_FALSE(result.revision.unsaved);
}

TEST(CfgSave, RejectsAConfigurationLoadedWithErrors) {
    SaveFixture fixture;
    auto const state = fixture.make_unsaved();
    bool file_called = false;

    auto const result = fixture.save(state.current_id, true, [&file_called] {
        file_called = true;
        return true;
    });

    EXPECT_EQ(result.status, sx::cfg::SaveStatus::partial_config);
    EXPECT_FALSE(file_called);
    EXPECT_TRUE(fixture.board.unsaved());
}

TEST(CfgSave, PreservesUnsavedStateAfterAFileError) {
    SaveFixture fixture;
    auto const state = fixture.make_unsaved();

    auto const result = fixture.save(state.current_id, false, [] { return false; });

    EXPECT_EQ(result.status, sx::cfg::SaveStatus::save_failed);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.revision.current_id, state.current_id);
    EXPECT_EQ(result.revision.saved_id, state.saved_id);
    EXPECT_TRUE(fixture.board.unsaved());
}

TEST(CfgSave, SavesTheExactRunningRevision) {
    SaveFixture fixture;
    auto const state = fixture.make_unsaved();
    bool file_called = false;

    auto const result = fixture.save(state.current_id, false, [&file_called] {
        file_called = true;
        return true;
    });

    EXPECT_EQ(result.status, sx::cfg::SaveStatus::saved);
    EXPECT_TRUE(result.ok());
    EXPECT_TRUE(result.changed());
    EXPECT_TRUE(file_called);
    EXPECT_EQ(result.revision.current_id, state.current_id);
    EXPECT_EQ(result.revision.saved_id, state.current_id);
    EXPECT_FALSE(result.revision.unsaved);
    EXPECT_EQ(fixture.board.updater(), "api:127.0.0.1");
}

TEST(CfgSave, HoldsTheConfigMutexUntilSavedStateIsPublished) {
    SaveFixture fixture;
    auto const state = fixture.make_unsaved();

    auto const result = fixture.save(state.current_id, false, [&fixture] {
        auto locked_elsewhere = std::async(std::launch::async, [&fixture] {
            const bool locked = fixture.config_mutex.try_lock();
            if(locked) fixture.config_mutex.unlock();
            return locked;
        });
        return !locked_elsewhere.get();
    });

    EXPECT_EQ(result.status, sx::cfg::SaveStatus::saved);
    EXPECT_FALSE(result.revision.unsaved);
}

TEST(CfgSave, ReleasesTheGateWhenTheFileWriterThrows) {
    SaveFixture fixture;
    auto const state = fixture.make_unsaved();

    EXPECT_THROW(
        fixture.save(state.current_id, false, []() -> bool {
            throw std::runtime_error("file writer failed");
        }),
        std::runtime_error);

    EXPECT_TRUE(fixture.board.unsaved());
    EXPECT_TRUE(fixture.gate.enter(fixture.config_mutex));
}
