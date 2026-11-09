#include <gtest/gtest.h>

#include <utils/fs.hpp>

#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

class TemporaryTree {
public:
    TemporaryTree() {
        auto pattern = (std::filesystem::temp_directory_path() /
                        "smithproxy-fs-test-XXXXXX").string();
        storage.assign(pattern.begin(), pattern.end());
        storage.push_back('\0');
        auto* created = ::mkdtemp(storage.data());
        if (created) root = created;
    }

    ~TemporaryTree() {
        if (!root.empty()) std::filesystem::remove_all(root);
    }

    std::vector<char> storage;
    std::filesystem::path root;
};

TEST(FileSystemUtils, DistinguishesFilesDirectoriesAndMissingPaths) {
    TemporaryTree tree;
    ASSERT_FALSE(tree.root.empty());
    auto const file = tree.root / "regular";
    std::ofstream(file) << "data";
    auto const missing = tree.root / "missing";

    EXPECT_TRUE(sx::fs::is_dir(tree.root.string()));
    EXPECT_FALSE(sx::fs::is_file(tree.root.string()));
    EXPECT_TRUE(sx::fs::is_file(file.string()));
    EXPECT_FALSE(sx::fs::is_dir(file.string()));
    EXPECT_FALSE(sx::fs::is_file(missing.string()));
    EXPECT_FALSE(sx::fs::is_dir(missing.string()));
}

TEST(FileSystemUtils, AcceptsOnlyExistingNonRootParentDirectories) {
    TemporaryTree tree;
    ASSERT_FALSE(tree.root.empty());
    auto const nested = tree.root / "nested";
    ASSERT_TRUE(std::filesystem::create_directory(nested));

    EXPECT_TRUE(sx::fs::is_basedir((nested / "output.log").string()));
    EXPECT_TRUE(sx::fs::is_basedir((nested / "output.log///").string()));
    EXPECT_FALSE(sx::fs::is_basedir((tree.root / "missing" / "output.log").string()));
    EXPECT_FALSE(sx::fs::is_basedir(tree.root.string()));
    EXPECT_FALSE(sx::fs::is_basedir(""));
    EXPECT_FALSE(sx::fs::is_basedir("/output.log"));
}

}  // namespace
