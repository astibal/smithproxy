#include <gtest/gtest.h>

#include <service/cfgapi/cfg_archive.hpp>
#include <service/cfgapi/cfg_archive_session.hpp>
#include <service/cfgapi/cfg_exposure.hpp>
#include <service/cfgapi/cfg_file_lock.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

namespace {

using sx::cfg::CfgArchiveSession;
using sx::cfg::CfgExposureRegistry;
using sx::cfg::CfgFileLock;
using sx::cfg::CfgManifest;
using sx::cfg::CfgTar;
using sx::cfg::CfgTarError;

class ArchiveSessionTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string pattern = "/tmp/smithproxy-cftar-session-test-XXXXXX";
        directory_ = ::mkdtemp(pattern.data());
        ASSERT_FALSE(directory_.empty());
        archive_path_ = directory_ + "/smithproxy.cftar";
        write_archive(valid_archive());
    }

    void TearDown() override {
        std::filesystem::remove_all(directory_);
    }

    CfgTar valid_archive() const {
        CfgTar archive;
        archive.add(std::string(CfgManifest::path), CfgManifest::canonical());
        archive.add("smithproxy.cfg", "settings : {};\n");
        archive.add("smithproxy.startup.cfg", "SMITH_RUN_TRANSPARENT=1\n");
        archive.add("messages/en/page.html", "original");
        return archive;
    }

    void write_archive(const CfgTar& archive) const {
        archive.write_file(archive_path_);
    }

    std::string directory_;
    std::string archive_path_;
};

TEST_F(ArchiveSessionTest, OpensValidatedArchiveAsCleanWorkingCopy) {
    const auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("messages/en/page.html").data, "original");
    EXPECT_EQ(session.base_hash().find("sha256:"), 0U);
}

TEST_F(ArchiveSessionTest, StagesAndDiscardsResourceChanges) {
    auto session = CfgArchiveSession::open(archive_path_);

    session.put("messages/en/page.html", "changed");
    session.put("scripts/inspect.macro", "show config");
    EXPECT_TRUE(session.dirty());
    ASSERT_EQ(session.changes().size(), 2U);

    session.discard();
    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("messages/en/page.html").data, "original");
    EXPECT_FALSE(session.archive().contains("scripts/inspect.macro"));
}

TEST_F(ArchiveSessionTest, RejectsInvalidMainConfigurationBeforeStaging) {
    auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_THROW(session.put("smithproxy.cfg", "settings : {"), CfgTarError);
    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("smithproxy.cfg").data, "settings : {};\n");
}

TEST_F(ArchiveSessionTest, RejectsRemovingControlFiles) {
    auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_THROW(session.remove("smithproxy.cfg"), CfgTarError);
    EXPECT_THROW(session.remove(CfgManifest::path), CfgTarError);
    EXPECT_FALSE(session.dirty());
}

TEST_F(ArchiveSessionTest, KeepsManifestUnderFormatControl) {
    auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_THROW(session.put(
                     std::string(CfgManifest::path), CfgManifest::canonical()),
                 CfgTarError);
    EXPECT_FALSE(session.dirty());
}

TEST_F(ArchiveSessionTest, SavesRecoveryCopyBeforeAtomicReplacement) {
    auto session = CfgArchiveSession::open(archive_path_);
    session.put("messages/en/page.html", "changed");

    session.save();

    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(CfgTar::read_file(archive_path_).at("messages/en/page.html").data,
              "changed");
    EXPECT_EQ(CfgTar::read_file(archive_path_ + ".previous.bak.cftar")
                  .at("messages/en/page.html").data,
              "original");
}

TEST_F(ArchiveSessionTest, RefusesToOverwriteAnExternallyChangedArchive) {
    auto session = CfgArchiveSession::open(archive_path_);
    session.put("messages/en/page.html", "session change");

    auto external = valid_archive();
    external.replace("messages/en/page.html", "external change");
    ASSERT_EQ(::unlink(archive_path_.c_str()), 0);
    write_archive(external);

    EXPECT_THROW(session.save(), CfgTarError);
    EXPECT_EQ(CfgTar::read_file(archive_path_).at("messages/en/page.html").data,
              "external change");
    EXPECT_FALSE(std::filesystem::exists(archive_path_ + ".previous.bak.cftar"));
}

TEST_F(ArchiveSessionTest, StableSidecarLockSerializesIndependentWriters) {
    auto first = CfgFileLock::acquire(archive_path_);

    EXPECT_THROW(
        CfgFileLock::acquire(archive_path_, std::chrono::milliseconds(30)),
        CfgTarError);
}

TEST_F(ArchiveSessionTest, ExposureIsReadOnlyAndLivesOnlyInRegistry) {
    const auto session = CfgArchiveSession::open(archive_path_);
    CfgExposureRegistry exposures;

    const auto exposure = exposures.expose(
        session.archive(), "messages/en/page.html");
    struct stat metadata {};
    ASSERT_EQ(::stat(exposure.filesystem_path.c_str(), &metadata), 0);
    EXPECT_EQ(metadata.st_mode & 0777, 0400);
    EXPECT_TRUE(std::filesystem::exists(exposure.filesystem_path));

    EXPECT_TRUE(exposures.close(exposure.id));
    EXPECT_FALSE(std::filesystem::exists(exposure.filesystem_path));
}

TEST_F(ArchiveSessionTest, RegistryDestructionClosesAllExposures) {
    const auto session = CfgArchiveSession::open(archive_path_);
    std::string path;
    {
        CfgExposureRegistry exposures;
        path = exposures.expose(session.archive(), "messages").filesystem_path;
        EXPECT_TRUE(std::filesystem::exists(path));
    }
    EXPECT_FALSE(std::filesystem::exists(path));
}

}  // namespace
