#include <gtest/gtest.h>

#include <service/cfgapi/cfg_archive.hpp>
#include <service/cfgapi/cfg_archive_monitor.hpp>
#include <service/privileged_file.hpp>
#include <service/reload/file_reload_service.hpp>

#include <chrono>
#include <filesystem>
#include <thread>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;
using sx::cfg::CfgArchiveMonitor;
using sx::cfg::CfgManifest;
using sx::cfg::CfgTar;
using sx::reload::FileReloadService;
using sx::reload::ReloadStatus;

class ArchiveMonitorTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string pattern = "/tmp/smithproxy-cftar-monitor-test-XXXXXX";
        directory_ = ::mkdtemp(pattern.data());
        ASSERT_FALSE(directory_.empty());
        archive_path_ = directory_ + "/smithproxy.cftar";
        initial_payload_ = archive("initial").write();
        ASSERT_EQ(sx::privsep::files::write_file_atomic(
                      archive_path_, initial_payload_), 0);
    }

    void TearDown() override {
        std::filesystem::remove_all(directory_);
    }

    CfgTar archive(std::string marker) const {
        CfgTar result;
        result.add(std::string(CfgManifest::path), CfgManifest::canonical());
        result.add("smithproxy.cfg", "settings : { marker = \"" + marker + "\"; };\n");
        result.add("smithproxy.startup.cfg", "SMITH_RUN_TRANSPARENT=1\n");
        return result;
    }

    CfgArchiveMonitor monitor() const {
        return CfgArchiveMonitor({archive_path_, initial_payload_});
    }

    template<class Predicate>
    bool wait_until(Predicate predicate, std::chrono::milliseconds timeout = 2s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while(std::chrono::steady_clock::now() < deadline) {
            if(predicate()) return true;
            std::this_thread::sleep_for(2ms);
        }
        return predicate();
    }

    std::string directory_;
    std::string archive_path_;
    std::string initial_payload_;
};

TEST_F(ArchiveMonitorTest, AcceptedInitialGenerationIsUnchanged) {
    auto watched = monitor();

    EXPECT_EQ(watched.reload_now().status, ReloadStatus::unchanged);
    EXPECT_FALSE(watched.change_detected());
    EXPECT_TRUE(watched.detected_hash().empty());
    EXPECT_TRUE(watched.last_error().empty());
}

TEST_F(ArchiveMonitorTest, ValidExternalReplacementRequiresRestart) {
    auto watched = monitor();
    const auto replacement = archive("external").write();
    ASSERT_EQ(sx::privsep::files::write_file_atomic(
                  archive_path_, replacement), 0);

    const auto result = watched.poll();

    EXPECT_EQ(result.status, ReloadStatus::published);
    EXPECT_EQ(result.version, 1U);
    EXPECT_TRUE(watched.change_detected());
    EXPECT_EQ(watched.detected_hash().find("sha256:"), 0U);
    EXPECT_TRUE(watched.last_error().empty());
}

TEST_F(ArchiveMonitorTest, AcceptedOwnWriteClearsTransientObservation) {
    auto watched = monitor();
    const auto replacement = archive("own-save").write();
    ASSERT_EQ(sx::privsep::files::write_file_atomic(
                  archive_path_, replacement), 0);
    ASSERT_EQ(watched.poll().status, ReloadStatus::published);

    watched.accept(replacement);

    EXPECT_FALSE(watched.change_detected());
    EXPECT_EQ(watched.poll().status, ReloadStatus::unchanged);
}

TEST_F(ArchiveMonitorTest, InvalidExternalReplacementStillRequiresRestart) {
    auto watched = monitor();
    ASSERT_EQ(sx::privsep::files::write_file_atomic(
                  archive_path_, "not a tar archive"), 0);

    const auto result = watched.poll();

    EXPECT_EQ(result.status, ReloadStatus::failed);
    EXPECT_TRUE(watched.change_detected());
    EXPECT_FALSE(watched.last_error().empty());
}

TEST_F(ArchiveMonitorTest, MissingArchiveIsAConservativeFailure) {
    auto watched = monitor();
    ASSERT_EQ(::unlink(archive_path_.c_str()), 0);

    EXPECT_EQ(watched.poll().status, ReloadStatus::failed);
    EXPECT_TRUE(watched.change_detected());
    EXPECT_NE(watched.last_error().find("cannot stat"), std::string::npos);
}

TEST_F(ArchiveMonitorTest, SharedReloadWorkerDetectsReplacement) {
    auto watched = std::make_shared<CfgArchiveMonitor>(
        CfgArchiveMonitor::Context{archive_path_, initial_payload_});
    FileReloadService service;
    ASSERT_NE(service.add(watched, 5ms), 0U);
    service.start();

    const auto replacement = archive("worker").write();
    ASSERT_EQ(sx::privsep::files::write_file_atomic(
                  archive_path_, replacement), 0);

    EXPECT_TRUE(wait_until([&] { return watched->change_detected(); }));
    service.stop();
}

}  // namespace
