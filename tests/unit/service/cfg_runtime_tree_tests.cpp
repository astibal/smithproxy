#include <gtest/gtest.h>

#include <service/cfgapi/cfg_runtime_tree.hpp>

#include <filesystem>
#include <fstream>

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
    archive.add("messages/en/page.html", "page");
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
