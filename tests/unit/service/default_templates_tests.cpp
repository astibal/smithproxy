#include <gtest/gtest.h>

#include <resources/default_templates.hpp>
#include <service/cfgapi/cfg_archive.hpp>
#include <service/cfgapi/cfg_pack.hpp>
#include <service/cfgapi/cfg_template_files.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using sx::cfg::CfgPack;
using sx::resources::default_templates::all;

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

TEST(DefaultTemplates, CompleteSetParsesIncludingEveryTheme) {
    sx::cfg::CfgTar templates;
    for(const auto& [name, content] : all()) templates.add(name, content);
    EXPECT_EQ(all().size(), 15);
    EXPECT_NO_THROW(sx::cfg::CfgTemplateFiles::validate(templates));
}

class DefaultTemplateMigration : public ::testing::Test {
protected:
    void SetUp() override {
        std::string pattern = "/tmp/default-templates-XXXXXX";
        const auto* directory = ::mkdtemp(pattern.data());
        ASSERT_NE(directory, nullptr);
        root_ = directory;
        input_.main_config = write("main.cfg", "settings : {};\n");
        input_.startup_config = write("startup.cfg", "");
        input_.resource_defaults = all();
        for(const auto& [path, content] : all()) {
            input_.files.push_back({path, (root_ / fs::path(path).filename()).string(), false, true});
        }
    }

    void TearDown() override { fs::remove_all(root_); }

    std::string write(const std::string& name, const std::string& content) {
        const auto path = root_ / name;
        std::ofstream(path, std::ios::binary) << content;
        return path.string();
    }

    fs::path root_;
    CfgPack::Input input_;
};

TEST_F(DefaultTemplateMigration, MissingLegacyDirectoryUsesCompleteDefaults) {
    const auto archive = CfgPack::build(input_);
    for(const auto& [path, content] : all()) {
        EXPECT_EQ(archive.at(path).data, content) << path;
    }
}

TEST_F(DefaultTemplateMigration, PreservesCustomAndEmptyLegacyTemplates) {
    write("html_page.txt", "custom page");
    write("tls_reason.txt", "");
    const auto archive = CfgPack::build(input_);
    EXPECT_EQ(archive.at("templates/replacement/en/html_page.txt").data, "custom page");
    EXPECT_EQ(archive.at("templates/replacement/en/tls_reason.txt").data, "");
    EXPECT_EQ(archive.at("templates/replacement/en/tls_replacement.txt").data,
              all().at("templates/replacement/en/tls_replacement.txt"));
}

TEST_F(DefaultTemplateMigration, DoesNotHideUnsafeExistingLegacyTemplate) {
    fs::create_symlink(root_ / "missing-target", root_ / "html_page.txt");
    EXPECT_THROW(CfgPack::build(input_), sx::cfg::CfgTarError);
    fs::remove(root_ / "html_page.txt");
    fs::create_directory(root_ / "html_page.txt");
    EXPECT_THROW(CfgPack::build(input_), sx::cfg::CfgTarError);
}

TEST_F(DefaultTemplateMigration, NativeUpgradePreservesCustomAndEmptyResources) {
    input_.files.clear();
    input_.resource_defaults.clear();
    input_.files.push_back({"templates/replacement/en/html_page.txt", write("page", "custom page")});
    input_.files.push_back({"templates/replacement/en/tls_reason.txt", write("reason", "")});
    const auto path = (root_ / "native.cftar").string();
    CfgPack::build(input_).write_file(path);
    auto source = sx::cfg::CfgArchive::read_archive(path, read_file(path));
    const auto prepared = source.prepare_save("settings : {};\n", all());
    const auto upgraded = sx::cfg::CfgTar::read(prepared.replacement);
    for(const auto& [name, content] : all()) {
        ASSERT_TRUE(upgraded.contains(name)) << name;
    }
    EXPECT_EQ(upgraded.at("templates/replacement/en/html_page.txt").data, "custom page");
    EXPECT_EQ(upgraded.at("templates/replacement/en/tls_reason.txt").data, "");
}

} // namespace
