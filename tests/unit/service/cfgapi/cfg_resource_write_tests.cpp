#include <gtest/gtest.h>

#include <service/cfgapi/cfg_resource_write.hpp>
#include <utils/crypto.hpp>

namespace {

class TestResourceArchive final : public sx::cfg::CfgArchiveStorage {
public:
    [[nodiscard]] bool available() const override {
        return available_override && source.has_value();
    }

    [[nodiscard]] std::string current() const override {
        return source->archive_payload();
    }

    [[nodiscard]] sx::cfg::CfgSaveData prepare_main(std::string) const override {
        throw std::logic_error("main preparation is not used by resource tests");
    }

    [[nodiscard]] sx::cfg::CfgSaveData prepare_resource(
        std::string path,
        std::optional<std::string> content,
        bool executable) const override {
        if(throw_from_prepare) throw std::runtime_error("injected prepare failure");
        return source->prepare_resource(
            std::move(path), std::move(content), executable);
    }

    [[nodiscard]] bool publish(const sx::cfg::CfgSaveData& data) const override {
        ++installs;
        installed = data.replacement;
        if(!install_ok) return false;
        source->accept_saved_archive(data.replacement);
        return true;
    }
    [[nodiscard]] bool restart_required() const override {
        return restart_needed;
    }
    void require_restart() override { restart_needed = true; }

    mutable std::optional<sx::cfg::CfgArchive> source;
    bool install_ok = true;
    bool available_override = true;
    bool throw_from_prepare = false;
    bool restart_needed = false;
    mutable int installs = 0;
    mutable std::string installed;
};

class ResourceWriteTest : public ::testing::Test {
protected:
    void SetUp() override {
        board.init_revision("snapshot", "startup");
        sx::cfg::CfgTar tar;
        tar.add(std::string(sx::cfg::CfgManifest::path),
                sx::cfg::CfgManifest::canonical());
        tar.add("smithproxy.cfg", "settings : {};\n");
        tar.add("smithproxy.startup.cfg", "START=1\n");
        archive.source = std::make_optional(
            sx::cfg::CfgArchive::read_archive("smithproxy.cftar", tar.write()));
    }

    sx::cfg::ResourceWriteResult write(
        std::string revision, std::string hash, std::string path,
        std::optional<std::string> content) {
        sx::cfg::CfgResourceWriter writer(
            {board, gate, mutex, archive});
        return writer.write(std::move(revision), std::move(hash), std::move(path),
                            std::move(content), false);
    }

    std::string hash() const {
        return "sha256:" + *sx::crypto::sha256(archive.source->archive_payload());
    }

    UpdateBoard board;
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex mutex;
    TestResourceArchive archive;
};

TEST_F(ResourceWriteTest, WritesAndAdoptsAResource) {
    const auto result = write(board.revision_current(), hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_TRUE(result.ok());
    EXPECT_TRUE(archive.restart_needed);
    EXPECT_EQ(archive.installs, 1);
    EXPECT_EQ(archive.source->resolve("templates/replacement/en/page.html", "legacy").content(), "page");
}

TEST_F(ResourceWriteTest, RejectsAStaleArchiveHash) {
    const auto result = write(board.revision_current(), "sha256:stale",
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::hash_mismatch);
    EXPECT_EQ(archive.installs, 0);
}

TEST_F(ResourceWriteTest, RejectsBusyLease) {
    ASSERT_TRUE(gate.acquire(
        board.revision_current(), "other-admin",
        [this] { return board.revision_current(); }));

    const auto result = write(board.revision_current(), hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::lease_busy);
}

TEST_F(ResourceWriteTest, RejectsStaleRunningRevision) {
    const auto result = write("stale-revision", hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::stale_revision);
}

TEST_F(ResourceWriteTest, RejectsUnavailableNativeArchive) {
    archive.available_override = false;

    const auto result = write(board.revision_current(), hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::native_unavailable);
}

TEST_F(ResourceWriteTest, RejectsUnsavedRunningConfiguration) {
    board.upgrade("cli", "changed", "set value");
    const auto result = write(board.revision_current(), hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::unsaved_running);
}

TEST_F(ResourceWriteTest, RejectsWriteAfterExternalArchiveReplacement) {
    archive.restart_needed = true;
    const auto result = write(board.revision_current(), hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::write_failed);
    EXPECT_EQ(result.detail, "startup archive changed and requires restart");
    EXPECT_EQ(archive.installs, 0);
}

TEST_F(ResourceWriteTest, DoesNotAdoptFailedStorageWrite) {
    archive.install_ok = false;
    const auto result = write(board.revision_current(), hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::write_failed);
    EXPECT_FALSE(archive.restart_needed);
    EXPECT_FALSE(archive.source->archive().contains("templates/replacement/en/page.html"));
}

TEST_F(ResourceWriteTest, RejectsControlFileMutation) {
    const auto result = write(board.revision_current(), hash(),
                              "manifest.json", std::string("bad"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::invalid_resource);
    EXPECT_EQ(archive.installs, 0);
}

TEST_F(ResourceWriteTest, ConvertsUnexpectedPrepareFailure) {
    archive.throw_from_prepare = true;

    const auto result = write(board.revision_current(), hash(),
                              "templates/replacement/en/page.html", std::string("page"));
    EXPECT_EQ(result.status, sx::cfg::ResourceWriteStatus::write_failed);
    EXPECT_EQ(result.detail, "injected prepare failure");
}

}  // namespace
