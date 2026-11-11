#include <gtest/gtest.h>

#include <service/cfgapi/cfg_runtime_tree.hpp>

#include <filesystem>
#include <fstream>

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
