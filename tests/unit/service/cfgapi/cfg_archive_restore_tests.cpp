#include <gtest/gtest.h>

#include <service/cfgapi/cfg_archive_restore.hpp>
#include <service/cfgapi/cfg_archive.hpp>
#include <utils/crypto.hpp>

#include <mutex>
#include <stdexcept>
#include <string>

namespace {

class ArchiveRestoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        board.init_revision("running snapshot", "startup");

        sx::cfg::CfgTar archive;
        archive.add(std::string(sx::cfg::CfgManifest::path),
                    sx::cfg::CfgManifest::canonical());
        archive.add("smithproxy.cfg", "settings : {};\n");
        archive.add("smithproxy.startup.cfg", "SMITH_RUN_TRANSPARENT=1\n");
        payload = archive.write();
        hash = "sha256:" + *sx::crypto::sha256(payload);
    }

    sx::cfg::ArchiveRestoreResult restore(
        std::string revision,
        std::string expected_hash,
        bool native = true,
        sx::cfg::ArchiveWriter writer = {}) {
        if(!writer) {
            writer = [this](const std::string& current, const std::string& replacement) {
                current_seen = current;
                replacement_seen = replacement;
                ++writes;
                return true;
            };
        }
        sx::cfg::CfgArchiveRestorer restorer({
            board,
            gate,
            config_mutex,
            native,
            restart_pending,
            [this] { return current_archive; },
            std::move(writer),
        });
        return restorer.restore(revision, expected_hash, payload);
    }

    UpdateBoard board;
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;
    bool restart_pending = false;
    int writes = 0;
    std::string current_archive = "current archive bytes";
    std::string current_seen;
    std::string replacement_seen;
    std::string payload;
    std::string hash;
};

TEST_F(ArchiveRestoreTest, RejectsAnInvalidArchiveBeforeEnteringTheWriter) {
    payload = "not a tar archive";
    const auto result = restore(board.revision_current(), "sha256:irrelevant");

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::invalid_archive);
    EXPECT_EQ(writes, 0);
    EXPECT_FALSE(restart_pending);
}

TEST_F(ArchiveRestoreTest, RejectsBytesDifferentFromTheValidatedHash) {
    const auto result = restore(board.revision_current(), "sha256:wrong");

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::hash_mismatch);
    EXPECT_EQ(result.content_hash, hash);
    EXPECT_EQ(writes, 0);
}

TEST_F(ArchiveRestoreTest, RejectsAnActiveTransactionLease) {
    ASSERT_TRUE(gate.acquire(
        board.revision_current(), "other-client",
        [this] { return board.revision_current(); }));

    const auto result = restore(board.revision_current(), hash);
    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::lease_busy);
    EXPECT_EQ(writes, 0);
}

TEST_F(ArchiveRestoreTest, RejectsAStaleRunningRevision) {
    const auto result = restore("stale-revision", hash);

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::stale_revision);
    EXPECT_EQ(result.revision.current_id, board.revision_current());
    EXPECT_EQ(writes, 0);
}

TEST_F(ArchiveRestoreTest, RejectsAnUnsavedRunningConfiguration) {
    board.upgrade("cli", "changed snapshot", "set settings.log_level");
    const auto result = restore(board.revision_current(), hash);

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::unsaved_running);
    EXPECT_EQ(writes, 0);
}

TEST_F(ArchiveRestoreTest, RejectsALegacyConfigurationSource) {
    const auto result = restore(board.revision_current(), hash, false);

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::native_unavailable);
    EXPECT_EQ(writes, 0);
}

TEST_F(ArchiveRestoreTest, RejectsASecondRestoreBeforeRestart) {
    restart_pending = true;
    const auto result = restore(board.revision_current(), hash);

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::restart_pending);
    EXPECT_EQ(writes, 0);
}

TEST_F(ArchiveRestoreTest, PreservesRunningStateWhenInstallationFails) {
    const auto before = board.revision_state();
    const auto result = restore(
        before.current_id, hash, true,
        [](const std::string&, const std::string&) { return false; });

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::write_failed);
    EXPECT_FALSE(restart_pending);
    EXPECT_EQ(board.revision_state().current_id, before.current_id);
    EXPECT_EQ(board.revision_state().saved_id, before.saved_id);
}

TEST_F(ArchiveRestoreTest, ConvertsWriterExceptionsIntoAControlledFailure) {
    const auto result = restore(
        board.revision_current(), hash, true,
        [](const std::string&, const std::string&) -> bool {
            throw std::runtime_error("disk error");
        });

    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::write_failed);
    EXPECT_EQ(result.detail, "disk error");
    EXPECT_FALSE(restart_pending);
}

TEST_F(ArchiveRestoreTest, InstallsExactBytesAndLeavesRunningRevisionUntouched) {
    const auto before = board.revision_state();
    const auto result = restore(before.current_id, hash);

    EXPECT_TRUE(result.ok());
    EXPECT_EQ(result.status, sx::cfg::ArchiveRestoreStatus::restored);
    EXPECT_EQ(result.content_hash, hash);
    EXPECT_EQ(writes, 1);
    EXPECT_EQ(current_seen, current_archive);
    EXPECT_EQ(replacement_seen, payload);
    EXPECT_TRUE(restart_pending);
    EXPECT_EQ(board.revision_state().current_id, before.current_id);
    EXPECT_EQ(board.revision_state().saved_id, before.saved_id);
}

}  // namespace
