#include <gtest/gtest.h>

#include <service/cfgapi/cfg_pack.hpp>
#include <service/cfgapi/cfg_archive.hpp>

#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

using sx::cfg::CfgPack;
using sx::cfg::CfgTarError;

class PackTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string pattern = "/tmp/smithproxy-cfg-pack-test-XXXXXX";
        directory_ = ::mkdtemp(pattern.data());
        ASSERT_FALSE(directory_.empty());

        input_.main_config = write("main.cfg", "settings : {};\n");
        input_.startup_config = write("startup.cfg", "SMITH_RUN_TRANSPARENT=1\n");
    }

    void TearDown() override {
        std::filesystem::remove_all(directory_);
    }

    std::string write(const std::string& name, const std::string& content) const {
        const auto path = directory_ + "/" + name;
        std::ofstream(path, std::ios::binary) << content;
        return path;
    }

    std::string write_native_archive() const {
        const auto path = directory_ + "/smithproxy.cftar";
        CfgPack::build(input_).write_file(path);
        return path;
    }

    std::string directory_;
    CfgPack::Input input_;
};

TEST_F(PackTest, BuildsCompleteValidatedArchive) {
    input_.files.push_back({"templates/replacement/en/replacement.txt", write("message", "hello"), false});
    input_.files.push_back({"commands/scripts/collect.sh", write("script", "#!/bin/sh\n"), true});

    const auto archive = CfgPack::build(input_);

    EXPECT_EQ(archive.at("smithproxy.cfg").data, "settings : {};\n");
    EXPECT_EQ(archive.at("smithproxy.startup.cfg").data, "SMITH_RUN_TRANSPARENT=1\n");
    EXPECT_EQ(archive.at("templates/replacement/en/replacement.txt").data, "hello");
    EXPECT_TRUE(archive.at("commands/scripts/collect.sh").executable);
}

TEST_F(PackTest, PreservesBinaryResourceData) {
    input_.files.push_back({"pki/ca/default/cert.der", write("cert", std::string("a\0b", 3)), false});

    const auto archive = CfgPack::build(input_);

    EXPECT_EQ(archive.at("pki/ca/default/cert.der").data, std::string("a\0b", 3));
}

TEST_F(PackTest, RejectsMissingRequiredInput) {
    input_.main_config.clear();
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RejectsIncompleteResourceAndDirectoryMappings) {
    input_.files.push_back({"templates/replacement/en/missing", "", false});
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);

    input_.files.clear();
    input_.directories.push_back({"pki/ca/default", ""});
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);

    input_.directories.clear();
    input_.directories.push_back({"", directory_});
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RejectsMigrationWithoutDestination) {
    EXPECT_THROW(CfgPack::migrate({input_, ""}), CfgTarError);
}

TEST_F(PackTest, RejectsSymlinkInput) {
    const auto link = directory_ + "/linked.cfg";
    ASSERT_EQ(::symlink(input_.main_config.c_str(), link.c_str()), 0);
    input_.main_config = link;

    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RejectsDirectoryInput) {
    input_.files.push_back({"templates/replacement/en/file", directory_, false});
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RejectsOversizedSparseInputBeforeAllocation) {
    const auto oversized = directory_ + "/oversized.cfg";
    const int fd = ::open(oversized.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::ftruncate(fd, 64LL * 1024LL * 1024LL + 1), 0);
    ASSERT_EQ(::close(fd), 0);
    input_.main_config = oversized;

    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RejectsDuplicateAndUnsupportedArchivePaths) {
    const auto resource = write("resource", "data");
    input_.files.push_back({"smithproxy.cfg", resource, false});
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);

    input_.files.clear();
    input_.files.push_back({"automation/action", resource, false});
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, MigratesLegacyFilesWithoutReplacingTheDestination) {
    const auto output = directory_ + "/smithproxy.cftar";
    const CfgPack::Migration migration {input_, output};

    EXPECT_TRUE(CfgPack::migrate(migration));
    EXPECT_EQ(sx::cfg::CfgTar::read_file(output).at("smithproxy.cfg").data,
              "settings : {};\n");

    write("main.cfg", "settings : { changed = true; };\n");
    EXPECT_FALSE(CfgPack::migrate(migration));
    EXPECT_EQ(sx::cfg::CfgTar::read_file(output).at("smithproxy.cfg").data,
              "settings : {};\n");
}

TEST_F(PackTest, CompletesTheLegacyReleaseTransitionEndToEnd) {
    const auto certificates = directory_ + "/certs/default";
    const auto messages = directory_ + "/msg/en";
    ASSERT_TRUE(std::filesystem::create_directories(certificates));
    ASSERT_TRUE(std::filesystem::create_directories(messages));
    std::ofstream(certificates + "/ca-cert.pem") << "certificate";
    std::ofstream(messages + "/replacement.txt") << "replacement page";

    input_.directories.push_back({"pki/ca/default", certificates});
    input_.directories.push_back({"templates/replacement/en", messages});
    const auto archive_path = directory_ + "/smithproxy.cftar";

    // A release upgrade first publishes and validates the complete native
    // archive while every legacy input is still available for recovery.
    ASSERT_TRUE(CfgPack::migrate({input_, archive_path}));
    const auto archive = sx::cfg::CfgTar::read_file(archive_path);
    EXPECT_EQ(archive.at("smithproxy.cfg").data, "settings : {};\n");
    EXPECT_EQ(archive.at("pki/ca/default/ca-cert.pem").data, "certificate");
    EXPECT_EQ(archive.at("templates/replacement/en/replacement.txt").data,
              "replacement page");

    // Retirement preserves the original tree as one memento before removing
    // its loose files. Repeating the startup sequence must be a no-op.
    const auto retired = CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar");
    EXPECT_TRUE(retired.backup_created);
    EXPECT_EQ(retired.files_removed, 4U);
    EXPECT_TRUE(std::filesystem::exists(archive_path));
    EXPECT_TRUE(std::filesystem::exists(
        directory_ + "/smithproxy.pre-cftar.tar"));
    EXPECT_FALSE(std::filesystem::exists(input_.main_config));
    EXPECT_FALSE(std::filesystem::exists(input_.startup_config));
    EXPECT_FALSE(std::filesystem::exists(directory_ + "/certs"));
    EXPECT_FALSE(std::filesystem::exists(directory_ + "/msg"));

    const auto repeated = CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar");
    EXPECT_FALSE(repeated.backup_created);
    EXPECT_EQ(repeated.files_removed, 0U);
    EXPECT_NO_THROW(sx::cfg::CfgManifest::validate(
        sx::cfg::CfgTar::read_file(archive_path)));
}

TEST_F(PackTest, RejectsInvalidExistingMigrationDestination) {
    const auto output = write("smithproxy.cftar", "not a tar archive");
    EXPECT_THROW(CfgPack::migrate({input_, output}), CfgTarError);
}

TEST_F(PackTest, RejectsSymlinkMigrationDestination) {
    const auto target = write("target.cftar", "untouched");
    const auto output = directory_ + "/smithproxy.cftar";
    ASSERT_EQ(::symlink(target.c_str(), output.c_str()), 0);

    EXPECT_THROW(CfgPack::migrate({input_, output}), CfgTarError);
    EXPECT_EQ(std::ifstream(target).peek(), 'u');
}

TEST_F(PackTest, LeavesNoArchiveWhenMigrationInputIsIncomplete) {
    const auto output = directory_ + "/smithproxy.cftar";
    input_.startup_config = directory_ + "/missing-startup.cfg";

    EXPECT_THROW(CfgPack::migrate({input_, output}), CfgTarError);
    EXPECT_FALSE(std::filesystem::exists(output));
}

TEST_F(PackTest, RepresentsAnAbsentOptionalStartupAsAnEmptyNativeEntry) {
    input_.startup_config = directory_ + "/missing-startup.cfg";
    input_.allow_missing_startup = true;

    const auto archive = CfgPack::build(input_);

    EXPECT_TRUE(archive.contains("smithproxy.startup.cfg"));
    EXPECT_TRUE(archive.at("smithproxy.startup.cfg").data.empty());
}

TEST_F(PackTest, OptionalStartupStillRejectsUnsafeExistingInput) {
    const auto link = directory_ + "/startup-link.cfg";
    ASSERT_EQ(::symlink(input_.startup_config.c_str(), link.c_str()), 0);
    input_.startup_config = link;
    input_.allow_missing_startup = true;

    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, SkipsAbsentOptionalResourceButPacksItWhenPresent) {
    input_.files.push_back({"pki/mitm/ssh/hostkeys/ed25519", directory_ + "/host-key", false, true});
    auto archive = CfgPack::build(input_);
    EXPECT_FALSE(archive.contains("pki/mitm/ssh/hostkeys/ed25519"));

    write("host-key", "private key");
    archive = CfgPack::build(input_);
    EXPECT_EQ(archive.at("pki/mitm/ssh/hostkeys/ed25519").data, "private key");
}

TEST_F(PackTest, OptionalResourceDoesNotHideUnsafeOrUnreadableInput) {
    const auto target = write("target", "data");
    const auto link = directory_ + "/optional-link";
    ASSERT_EQ(::symlink(target.c_str(), link.c_str()), 0);
    input_.files.push_back({"commands/scripts/link", link, false, true});

    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RecursivelyPacksAClosedResourceDirectory) {
    const auto root = directory_ + "/certs";
    ASSERT_TRUE(std::filesystem::create_directories(root + "/sni/example.org"));
    std::ofstream(root + "/ca-cert.pem") << "ca";
    std::ofstream(root + "/sni/example.org/key.pem") << "key";
    std::ofstream(root + "/sni/example.org/fullchain.pem") << "chain";
    input_.directories.push_back({"pki/ca/default", root});

    const auto archive = CfgPack::build(input_);
    EXPECT_EQ(archive.at("pki/ca/default/ca-cert.pem").data, "ca");
    EXPECT_EQ(archive.at("pki/ca/default/sni/example.org/key.pem").data, "key");
    EXPECT_EQ(archive.at("pki/ca/default/sni/example.org/fullchain.pem").data, "chain");
}

TEST_F(PackTest, RejectsSymlinksInResourceDirectory) {
    const auto root = directory_ + "/certs";
    ASSERT_TRUE(std::filesystem::create_directories(root));
    const auto target = write("outside-key", "secret");
    ASSERT_EQ(::symlink(target.c_str(), (root + "/key.pem").c_str()), 0);
    input_.directories.push_back({"pki/ca/default", root});

    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RejectsSpecialFilesInResourceDirectory) {
    const auto root = directory_ + "/resources";
    ASSERT_TRUE(std::filesystem::create_directories(root));
    ASSERT_EQ(::mkfifo((root + "/stream").c_str(), 0600), 0);
    input_.directories.push_back({"templates/replacement/en", root});

    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, SkipsOnlyAnAbsentOptionalResourceDirectory) {
    input_.directories.push_back({
        "pki/ca/default", directory_ + "/missing-certs", true});
    EXPECT_NO_THROW(CfgPack::build(input_));

    const auto target = directory_ + "/linked-certs";
    ASSERT_EQ(::symlink(directory_.c_str(), target.c_str()), 0);
    input_.directories.back().source_path = target;
    EXPECT_THROW(CfgPack::build(input_), CfgTarError);
}

TEST_F(PackTest, RetiresLegacyTreeOnlyAfterCreatingMemento) {
    write_native_archive();
    ASSERT_TRUE(std::filesystem::create_directories(directory_ + "/certs/default"));
    std::ofstream(directory_ + "/certs/default/key.pem") << "private key";
    write("smithproxy.cftar.lock", "publication lock");

    const auto result = CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar");

    EXPECT_TRUE(result.backup_created);
    EXPECT_EQ(result.files_removed, 3U);
    EXPECT_TRUE(std::filesystem::exists(directory_ + "/smithproxy.cftar"));
    EXPECT_TRUE(std::filesystem::exists(directory_ + "/smithproxy.cftar.lock"));
    EXPECT_FALSE(std::filesystem::exists(input_.main_config));
    EXPECT_FALSE(std::filesystem::exists(input_.startup_config));
    EXPECT_FALSE(std::filesystem::exists(directory_ + "/certs"));

    const auto backup = sx::cfg::CfgTar::read_file(
        directory_ + "/smithproxy.pre-cftar.tar");
    EXPECT_EQ(backup.at("etc/smithproxy/main.cfg").data, "settings : {};\n");
    EXPECT_EQ(backup.at("etc/smithproxy/certs/default/key.pem").data,
              "private key");
}

TEST_F(PackTest, ContinuesInterruptedRetirementAgainstImmutableMemento) {
    write_native_archive();
    CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar");

    // Recreate one byte-identical survivor as if the first cleanup stopped
    // before unlinking it. The existing memento authorizes only this content.
    input_.main_config = write("main.cfg", "settings : {};\n");
    const auto result = CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar");

    EXPECT_FALSE(result.backup_created);
    EXPECT_EQ(result.files_removed, 1U);
    EXPECT_FALSE(std::filesystem::exists(input_.main_config));
}

TEST_F(PackTest, RejectsLegacyContentChangedAfterMementoCreation) {
    write_native_archive();
    CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar");
    input_.main_config = write("main.cfg", "settings : { changed = true; };\n");

    EXPECT_THROW(CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar"), CfgTarError);
    EXPECT_TRUE(std::filesystem::exists(input_.main_config));
}

TEST_F(PackTest, RejectsUnsafeEntryBeforeCreatingRetirementMemento) {
    write_native_archive();
    ASSERT_EQ(::symlink(input_.main_config.c_str(),
                        (directory_ + "/legacy-link").c_str()), 0);

    EXPECT_THROW(CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar"), CfgTarError);
    EXPECT_FALSE(std::filesystem::exists(
        directory_ + "/smithproxy.pre-cftar.tar"));
    EXPECT_TRUE(std::filesystem::exists(input_.main_config));
}

TEST_F(PackTest, RejectsRetirementWithoutValidNativeArchive) {
    write("smithproxy.cftar", "broken");

    EXPECT_THROW(CfgPack::retire_legacy_tree(
        directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar"), CfgTarError);
    EXPECT_TRUE(std::filesystem::exists(input_.main_config));
}

} // namespace

TEST_F(PackTest, RetiresOnlyTheNativeSiblingAndPreservesPreviousBackup) {
    const auto native = directory_ + "/main.cftar";
    const auto old = write("main.cfg.old", "previous backup");
    EXPECT_EQ(CfgPack::retire_legacy_config(native), input_.main_config + ".old.1");
    EXPECT_FALSE(std::filesystem::exists(input_.main_config));
    std::ifstream saved(old);
    std::string contents;
    std::getline(saved, contents);
    EXPECT_EQ(contents, "previous backup");
    EXPECT_TRUE(std::filesystem::exists(input_.startup_config));
    EXPECT_TRUE(CfgPack::retire_legacy_config(native).empty());
}

TEST_F(PackTest, RetiresLegacyConfigWithoutChangingItsPermissions) {
    ASSERT_EQ(::chmod(input_.main_config.c_str(), 0600), 0);
    const auto backup = CfgPack::retire_legacy_config(directory_ + "/main.cftar");
    EXPECT_EQ(backup, input_.main_config + ".old");
    struct stat state {};
    ASSERT_EQ(::stat(backup.c_str(), &state), 0);
    EXPECT_EQ(state.st_mode & 0777, 0600);
}

TEST_F(PackTest, RefusesToRetireSymlinkOrNonNativePath) {
    ASSERT_EQ(::symlink(input_.main_config.c_str(), (directory_ + "/linked.cfg").c_str()), 0);
    EXPECT_THROW(CfgPack::retire_legacy_config(directory_ + "/linked.cftar"), CfgTarError);
    EXPECT_THROW(CfgPack::retire_legacy_config(input_.main_config), CfgTarError);
    EXPECT_TRUE(std::filesystem::exists(input_.main_config));
}

TEST_F(PackTest, LegacyTreeCleanupKeepsRetiredConfigBackups) {
    write_native_archive();
    const auto backup = write("smithproxy.cfg.old", "original configuration");
    CfgPack::retire_legacy_tree(directory_, "smithproxy.cftar", "smithproxy.pre-cftar.tar");
    EXPECT_TRUE(std::filesystem::exists(backup));
}

TEST_F(PackTest, RetiresActualExtensionlessInputOnlyForItsOwnArchive) {
    const auto source = write("tenant-office", "settings : {};\n");
    EXPECT_THROW(CfgPack::retire_legacy_config(directory_ + "/other.cftar", source), CfgTarError);
    EXPECT_TRUE(std::filesystem::exists(source));
    EXPECT_EQ(CfgPack::retire_legacy_config(source + ".cftar", source), source + ".old");
    EXPECT_FALSE(std::filesystem::exists(source));
}
