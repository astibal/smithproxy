#include <gtest/gtest.h>

#include <resources/default_templates.hpp>
#include <service/cfgapi/cfg_template_maintenance.hpp>
#include <service/cfgapi/cfg_template_files.hpp>
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace {

using namespace sx::cfg;

class TemplateStorage final : public CfgArchiveStorage {
public:
    bool available() const override { return native; }
    std::string current() const override { return payload; }
    CfgSaveData prepare_main(std::string) const override { throw std::logic_error("unused"); }
    CfgSaveData prepare_resource(std::string, std::optional<std::string>, bool) const override {
        throw std::logic_error("unused");
    }
    bool publish(const CfgSaveData& data) const override {
        ++writes;
        if(throw_on_write) throw CfgTarError("injected storage failure");
        if(fail_write) return false;
        previous = data.previous.value();
        payload = data.replacement;
        return true;
    }
    bool restart_required() const override { return pending; }
    void require_restart() override { pending = true; }

    bool native = true;
    bool pending = false;
    bool fail_write = false;
    bool throw_on_write = false;
    mutable int writes = 0;
    mutable std::string payload;
    mutable std::string previous;
};

class TemplateMaintenanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        board.init_revision("initial", "startup");
        CfgTar tar;
        tar.add(std::string(CfgManifest::path), CfgManifest::canonical());
        tar.add("smithproxy.cfg", "settings : {};\n");
        tar.add("smithproxy.startup.cfg", "START=1\n");
        tar.add("templates/replacement/en/html_page.txt", "custom page");
        tar.add("templates/replacement/en/tls_reason.txt", "");
        tar.add("templates/replacement/en/user.txt", "user-only template");
        tar.add("pki/ca/default/ca-cert.pem", "untouched certificate");
        storage.payload = tar.write();
    }

    std::size_t apply(TemplateMaintenance mode) {
        return CfgTemplateMaintainer({board, gate, mutex, storage}).apply(mode);
    }

    UpdateBoard board;
    CfgWriteGate gate;
    std::recursive_mutex mutex;
    TemplateStorage storage;
};

TEST_F(TemplateMaintenanceTest, FixMissingPreservesCustomEmptyAndUnrelatedResources) {
    const auto before = storage.payload;
    EXPECT_EQ(apply(TemplateMaintenance::fix_missing), sx::resources::default_templates::all().size() - 2);
    const auto archive = CfgTar::read(storage.payload);
    EXPECT_EQ(archive.at("templates/replacement/en/html_page.txt").data, "custom page");
    EXPECT_EQ(archive.at("templates/replacement/en/tls_reason.txt").data, "");
    EXPECT_EQ(archive.at("templates/replacement/en/user.txt").data, "user-only template");
    EXPECT_EQ(archive.at("pki/ca/default/ca-cert.pem").data, "untouched certificate");
    EXPECT_EQ(storage.previous, before);
    EXPECT_EQ(storage.writes, 1);
    EXPECT_TRUE(storage.pending);
    EXPECT_FALSE(board.revision_state().unsaved);
}

TEST_F(TemplateMaintenanceTest, RollbackReplacesAllShippedTemplatesInOnePublication) {
    const auto original = CfgTar::read(storage.payload);
    EXPECT_EQ(apply(TemplateMaintenance::rollback), sx::resources::default_templates::all().size());
    const auto archive = CfgTar::read(storage.payload);
    for(const auto& [name, content] : sx::resources::default_templates::all()) {
        EXPECT_EQ(archive.at(name).data, content);
        EXPECT_FALSE(archive.at(name).executable);
    }
    for(const auto& name : {"smithproxy.cfg", "smithproxy.startup.cfg",
                           "templates/replacement/en/user.txt", "pki/ca/default/ca-cert.pem"}) {
        EXPECT_EQ(archive.at(name).data, original.at(name).data);
    }
    EXPECT_EQ(storage.writes, 1);
}

TEST_F(TemplateMaintenanceTest, NoOpDoesNotWriteOrReplaceBackup) {
    apply(TemplateMaintenance::rollback);
    storage.pending = false; // Simulate activation after restart.
    const auto saved = storage.payload;
    const auto backup = storage.previous;
    EXPECT_EQ(apply(TemplateMaintenance::rollback), 0);
    EXPECT_EQ(apply(TemplateMaintenance::fix_missing), 0);
    EXPECT_EQ(storage.writes, 1);
    EXPECT_EQ(storage.payload, saved);
    EXPECT_EQ(storage.previous, backup);
    EXPECT_FALSE(storage.pending);
}

TEST_F(TemplateMaintenanceTest, RollbackRemovesExecutableBit) {
    apply(TemplateMaintenance::rollback);
    auto tar = CfgTar::read(storage.payload);
    const auto path = "templates/replacement/en/html_page.txt";
    tar.replace(path, tar.at(path).data, true);
    storage.payload = tar.write();
    storage.pending = false;
    EXPECT_EQ(apply(TemplateMaintenance::rollback), 1);
    EXPECT_FALSE(CfgTar::read(storage.payload).at(path).executable);
}

TEST_F(TemplateMaintenanceTest, RejectsUnsavedConfiguration) {
    board.upgrade("test", "changed", "test edit");
    EXPECT_THROW(apply(TemplateMaintenance::rollback), CfgTarError);
    EXPECT_EQ(storage.writes, 0);
}

TEST_F(TemplateMaintenanceTest, RejectsLegacyAndPendingArchives) {
    storage.native = false;
    EXPECT_THROW(apply(TemplateMaintenance::fix_missing), CfgTarError);
    storage.native = true;
    storage.pending = true;
    EXPECT_THROW(apply(TemplateMaintenance::rollback), CfgTarError);
    EXPECT_EQ(storage.writes, 0);
}

TEST_F(TemplateMaintenanceTest, RejectsActiveLease) {
    auto grant = gate.acquire(board.revision_current(), "test",
                              [&] { return board.revision_current(); });
    ASSERT_TRUE(grant);
    EXPECT_THROW(apply(TemplateMaintenance::rollback), CfgTarError);
    EXPECT_EQ(storage.writes, 0);
}

TEST_F(TemplateMaintenanceTest, PublicationFailuresPreserveWriteBase) {
    const auto before = storage.payload;
    storage.fail_write = true;
    EXPECT_THROW(apply(TemplateMaintenance::rollback), CfgTarError);
    storage.fail_write = false;
    storage.throw_on_write = true;
    EXPECT_THROW(apply(TemplateMaintenance::fix_missing), CfgTarError);
    EXPECT_EQ(storage.payload, before);
    EXPECT_FALSE(storage.pending);
}

TEST_F(TemplateMaintenanceTest, CorruptArchiveFailsWithoutPublication) {
    storage.payload = "invalid archive";
    EXPECT_THROW(apply(TemplateMaintenance::rollback), CfgTarError);
    EXPECT_EQ(storage.writes, 0);
}

class TemplateTransferTest : public TemplateMaintenanceTest {
protected:
    void SetUp() override {
        TemplateMaintenanceTest::SetUp();
        apply(TemplateMaintenance::fix_missing);
        storage.pending = false;
        std::string pattern = "/tmp/template-transfer-XXXXXX";
        const auto* created = ::mkdtemp(pattern.data());
        ASSERT_NE(created, nullptr);
        root = created;
        directory = (root / "export").string();
    }
    void TearDown() override { std::filesystem::remove_all(root); }
    CfgTemplateMaintainer maintainer() { return CfgTemplateMaintainer({board, gate, mutex, storage}); }
    void write(const std::string& name, const std::string& bytes) {
        std::ofstream(std::filesystem::path(directory) / "en" / name, std::ios::binary) << bytes;
    }
    std::filesystem::path root;
    std::string directory;
};

TEST_F(TemplateTransferTest, ExportsCurrentContentAndImportsCompleteEditedSet) {
    maintainer().export_directory(directory);
    const auto original = storage.payload;
    EXPECT_EQ(CfgTemplateFiles::read(directory).at("templates/replacement/en/html_page.txt").data, "custom page");
    EXPECT_EQ(maintainer().import_directory(directory), 0);
    EXPECT_EQ(storage.payload, original);
    write("html_page.txt", "edited page");
    EXPECT_EQ(maintainer().import_directory(directory), 1);
    EXPECT_EQ(storage.previous, original);
    EXPECT_EQ(CfgTar::read(storage.payload).at("templates/replacement/en/html_page.txt").data, "edited page");
    EXPECT_TRUE(storage.pending);
}

TEST_F(TemplateTransferTest, ExportRefusesExistingDirectoryAndLegacyStorage) {
    maintainer().export_directory(directory);
    EXPECT_THROW(maintainer().export_directory(directory), CfgTarError);
    storage.native = false;
    EXPECT_THROW(maintainer().export_directory((root / "other").string()), CfgTarError);
}

TEST_F(TemplateTransferTest, IncompleteUnknownAndForeignLanguageSetsDoNotPublish) {
    maintainer().export_directory(directory);
    const auto original = storage.payload;
    std::filesystem::remove(std::filesystem::path(directory) / "en/tls_reason.txt");
    EXPECT_THROW(maintainer().import_directory(directory), CfgTarError);
    write("unknown.txt", "unknown"); // Same count, wrong membership.
    EXPECT_THROW(maintainer().import_directory(directory), CfgTarError);
    std::filesystem::remove(std::filesystem::path(directory) / "en/unknown.txt");
    write("tls_reason.txt", "");
    std::filesystem::create_directory(std::filesystem::path(directory) / "cs");
    EXPECT_THROW(maintainer().import_directory(directory), CfgTarError);
    EXPECT_EQ(storage.payload, original);
}

TEST_F(TemplateTransferTest, SymlinksDirectoriesAndOversizedTemplatesAreRejected) {
    maintainer().export_directory(directory);
    const auto file = std::filesystem::path(directory) / "en/tls_reason.txt";
    std::filesystem::remove(file);
    std::filesystem::create_symlink(root / "missing", file);
    EXPECT_THROW(maintainer().import_directory(directory), CfgTarError);
    std::filesystem::remove(file);
    std::filesystem::create_directory(file);
    EXPECT_THROW(maintainer().import_directory(directory), CfgTarError);
    std::filesystem::remove(file);
    write("tls_reason.txt", std::string(1024 * 1024 + 1, 'x'));
    EXPECT_THROW(maintainer().import_directory(directory), CfgTarError);
}

TEST_F(TemplateTransferTest, TemplateSyntaxAndIncludesAreValidatedBeforePublication) {
    maintainer().export_directory(directory);
    const auto original = storage.payload;
    for(const auto& content : {"{% block broken %}", "{% include missing.txt %}",
                               "{% include tls_reason.txt %}"}) {
        write("tls_reason.txt", content);
        EXPECT_THROW(maintainer().import_directory(directory), std::exception);
        EXPECT_EQ(storage.payload, original);
    }
}

TEST_F(TemplateTransferTest, MissingInputAndRootSymlinkAreRejected) {
    EXPECT_THROW(maintainer().import_directory(directory), std::exception);
    maintainer().export_directory(directory);
    std::filesystem::create_directory_symlink(directory, root / "link");
    EXPECT_THROW(maintainer().import_directory((root / "link").string()), CfgTarError);
}

} // namespace
