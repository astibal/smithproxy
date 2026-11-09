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

    std::string directory_;
    CfgPack::Input input_;
};

TEST_F(PackTest, BuildsCompleteValidatedArchive) {
    input_.files.push_back({"messages/en/replacement.txt", write("message", "hello"), false});
    input_.files.push_back({"scripts/collect.sh", write("script", "#!/bin/sh\n"), true});

    const auto archive = CfgPack::build(input_);

    EXPECT_EQ(archive.at("smithproxy.cfg").data, "settings : {};\n");
    EXPECT_EQ(archive.at("smithproxy.startup.cfg").data, "SMITH_RUN_TRANSPARENT=1\n");
    EXPECT_EQ(archive.at("messages/en/replacement.txt").data, "hello");
    EXPECT_TRUE(archive.at("scripts/collect.sh").executable);
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
    input_.files.push_back({"messages/en/missing", "", false});
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
    input_.files.push_back({"messages/en/file", directory_, false});
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

TEST_F(PackTest, SkipsAbsentOptionalResourceButPacksItWhenPresent) {
    input_.files.push_back({"ssh/host-key", directory_ + "/host-key", false, true});
    auto archive = CfgPack::build(input_);
    EXPECT_FALSE(archive.contains("ssh/host-key"));

    write("host-key", "private key");
    archive = CfgPack::build(input_);
    EXPECT_EQ(archive.at("ssh/host-key").data, "private key");
}

TEST_F(PackTest, OptionalResourceDoesNotHideUnsafeOrUnreadableInput) {
    const auto target = write("target", "data");
    const auto link = directory_ + "/optional-link";
    ASSERT_EQ(::symlink(target.c_str(), link.c_str()), 0);
    input_.files.push_back({"scripts/link", link, false, true});

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
    input_.directories.push_back({"messages/en", root});

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

} // namespace
