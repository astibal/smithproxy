#include <gtest/gtest.h>
#include <service/cfgapi/cfgapi.hpp>
#include <service/cfgapi/cfg_runtime_tree.hpp>
#include <service/cfgapi/cfg_archive.hpp>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

TEST(SmithproxyRuntimeIo, MaterializesPrivateApplicationPathAndCleansItUp) {
    sx::cfg::ArchiveSchema schema;
    schema.format = "runtime-test";
    schema.required_files = {"payload"};
    sx::cfg::CfgTar archive;
    archive.add("manifest.json", sx::cfg::CfgManifest::canonical(schema));
    archive.add("payload", "configuration");

    std::filesystem::path generation;
    {
        auto runtime = sx::cfg::CfgRuntimeTree::create(
            schema, archive, std::make_shared<sx::cfg::SmithproxyRuntimeIo>());
        generation = std::filesystem::path(runtime.root()).parent_path();
        EXPECT_EQ(generation.string().find("/tmp/smithproxy-cftar-runtime-"), 0U);
        struct stat metadata {};
        ASSERT_EQ(::stat(generation.c_str(), &metadata), 0);
        EXPECT_EQ(metadata.st_mode & 0777, 0700);

        std::ifstream input(runtime.root() + "/payload");
        std::string content;
        input >> content;
        EXPECT_EQ(content, "configuration");
    }
    EXPECT_FALSE(std::filesystem::exists(generation));
}
