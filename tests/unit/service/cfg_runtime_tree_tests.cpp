#include <gtest/gtest.h>

#include <service/cfgapi/cfg_runtime_tree.hpp>

#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>

namespace {

class FailedRuntimeIo : public sx::cfg::CfgIo {
public:
    int create_temp_directory(std::string&) const override {
        return -1;
    }
};

}  // namespace

TEST(CfgRuntimeTree, MaterializesAndRemovesPrivateGeneration) {
    sx::cfg::CfgTar archive;
    archive.add("pki/ca/default/sni/example.org/key.pem", "key");

    std::string root;
    {
        auto runtime = sx::cfg::CfgRuntimeTree::create(archive);
        root = runtime.root();
        EXPECT_TRUE(std::filesystem::exists(
            root + "/pki/ca/default/sni/example.org/key.pem"));
        std::ifstream input(root + "/pki/ca/default/sni/example.org/key.pem");
        std::string content;
        input >> content;
        EXPECT_EQ(content, "key");
    }
    EXPECT_FALSE(std::filesystem::exists(root));
}

TEST(CfgRuntimeTree, MoveTransfersGenerationOwnership) {
    sx::cfg::CfgTar archive;
    archive.add("templates/replacement/en/page.html", "page");
    std::string root;
    {
        auto first = sx::cfg::CfgRuntimeTree::create(archive);
        root = first.root();
        auto second = std::move(first);
        EXPECT_EQ(second.root(), root);
        EXPECT_TRUE(std::filesystem::exists(root));
    }
    EXPECT_FALSE(std::filesystem::exists(root));
}

TEST(CfgRuntimeTree, MoveAssignmentCleansPreviousGeneration) {
    sx::cfg::CfgTar first_archive;
    first_archive.add("templates/replacement/en/first.html", "first");
    sx::cfg::CfgTar second_archive;
    second_archive.add("templates/replacement/en/second.html", "second");

    auto first = sx::cfg::CfgRuntimeTree::create(first_archive);
    auto second = sx::cfg::CfgRuntimeTree::create(second_archive);
    const auto old_first_root = first.root();
    const auto second_root = second.root();

    first = std::move(second);

    EXPECT_FALSE(std::filesystem::exists(old_first_root));
    EXPECT_EQ(first.root(), second_root);
    EXPECT_TRUE(std::filesystem::exists(second_root));
}

TEST(CfgRuntimeTree, FailedMaterializationCleansPartialGeneration) {
    sx::cfg::CfgTar archive;
    archive.add("templates", "blocks the directory");
    archive.add("templates/replacement/en/page.html", "page");

    EXPECT_THROW(
        sx::cfg::CfgRuntimeTree::create(archive),
        sx::cfg::CfgTarError);
}

TEST(CfgRuntimeTree, ReportsTemporaryGenerationCreationFailure) {
    sx::cfg::CfgTar archive;
    archive.add("smithproxy.cfg", "settings : {};\n");

    EXPECT_THROW(
        sx::cfg::CfgRuntimeTree::create(
            archive, std::make_shared<FailedRuntimeIo>()),
        sx::cfg::CfgTarError);
    EXPECT_THROW(
        sx::cfg::CfgRuntimeTree::create(archive, nullptr),
        sx::cfg::CfgTarError);
}

TEST(CfgRuntimeTree, OwnershipTransferPreservesPrivateModesAndMovedFromIsHarmless) {
    sx::cfg::CfgTar archive;
    archive.add("pki/example/key.pem", "private fixture");
    auto original = sx::cfg::CfgRuntimeTree::create(archive);
    auto runtime = std::move(original);
    EXPECT_NO_THROW(original.transfer_owner(getuid(), getgid()));
    runtime.transfer_owner(getuid(), getgid());

    const auto generation = std::filesystem::path(runtime.root()).parent_path();
    for(const auto& entry : std::filesystem::recursive_directory_iterator(generation)) {
        struct stat state {};
        ASSERT_EQ(::lstat(entry.path().c_str(), &state), 0);
        EXPECT_EQ(state.st_uid, getuid());
        EXPECT_EQ(state.st_gid, getgid());
        EXPECT_EQ(state.st_mode & 0077, 0);
    }
}

TEST(CfgRuntimeTree, OwnershipTransferRejectsSymlinksBeforeChangingFiles) {
    sx::cfg::CfgTar archive;
    archive.add("payload", "fixture");
    auto runtime = sx::cfg::CfgRuntimeTree::create(archive);
    std::filesystem::create_symlink("/etc/passwd", runtime.root() + "/unexpected");
    EXPECT_THROW(runtime.transfer_owner(getuid(), getgid()), sx::cfg::CfgTarError);
}

TEST(CfgRuntimeTree, OwnershipFailureIsReported) {
    const auto child = fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        if(geteuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) std::exit(2);
        int result = 1;
        {
            sx::cfg::CfgTar archive;
            archive.add("payload", "fixture");
            auto runtime = sx::cfg::CfgRuntimeTree::create(archive);
            try { runtime.transfer_owner(0, 0); }
            catch(const sx::cfg::CfgTarError&) { result = 0; }
        }
        std::exit(result);
    }
    int status = 0;
    ASSERT_EQ(waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}
