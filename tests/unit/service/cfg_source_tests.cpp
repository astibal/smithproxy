#include <gtest/gtest.h>

#include <service/cfgapi/cfg_source.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace {

using sx::cfg::CfgManifest;
using sx::cfg::CfgResource;
using sx::cfg::CfgSource;
using sx::cfg::CfgTar;
using sx::cfg::CfgTarError;

class SourceTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string pattern = "/tmp/smithproxy-cfg-source-test-XXXXXX";
        directory_ = ::mkdtemp(pattern.data());
        ASSERT_FALSE(directory_.empty());
        paths_.archive = directory_ + "/smithproxy.cftar";
        paths_.legacy = directory_ + "/smithproxy.cfg";
    }

    void TearDown() override {
        std::filesystem::remove_all(directory_);
    }

    CfgTar valid_archive() const {
        CfgTar archive;
        archive.add(std::string(CfgManifest::path), CfgManifest::canonical());
        archive.add("smithproxy.cfg", "settings : {};\n");
        archive.add("smithproxy.startup.cfg", "SMITH_RUN_TRANSPARENT=1\n");
        return archive;
    }

    void write_archive(const CfgTar& archive) const {
        archive.write_file(paths_.archive);
    }

    std::string directory_;
    CfgSource::Paths paths_;
};

TEST_F(SourceTest, CanonicalManifestIsStable) {
    EXPECT_EQ(CfgManifest::canonical(),
              "{\n  \"format\": \"smithproxy-cftar\",\n  \"version\": 1\n}\n");
}

TEST_F(SourceTest, ValidatesKnownResourceNamespaces) {
    auto archive = valid_archive();
    archive.add("pki/ca/default/ca-cert.pem", "certificate");
    archive.add("messages/en/tls-replacement.html", "message");
    archive.add("scripts/disable-capture.macro", "set capture off");
    archive.add("scripts/collect-debug.sh", "#!/bin/sh\n", true);
    archive.add("ssh/host-key", "key");

    EXPECT_NO_THROW(CfgManifest::validate(archive));
}

TEST_F(SourceTest, RecognizesOnlyResourceNamespaces) {
    EXPECT_TRUE(CfgManifest::is_resource_path("pki/ca/default/cert.pem"));
    EXPECT_TRUE(CfgManifest::is_resource_path("messages/en/page.html"));
    EXPECT_TRUE(CfgManifest::is_resource_path("scripts/action.macro"));
    EXPECT_TRUE(CfgManifest::is_resource_path("ssh/host-key"));

    EXPECT_FALSE(CfgManifest::is_resource_path("pki/"));
    EXPECT_FALSE(CfgManifest::is_resource_path("smithproxy.cfg"));
    EXPECT_FALSE(CfgManifest::is_resource_path("unknown/file"));
    EXPECT_FALSE(CfgManifest::is_resource_path("ssh/../host-key"));
    EXPECT_FALSE(CfgManifest::is_resource_path("messages//page.html"));
}

TEST_F(SourceTest, RejectsMissingOrInvalidManifest) {
    CfgTar missing;
    missing.add("smithproxy.cfg", "config");
    missing.add("smithproxy.startup.cfg", "startup");
    EXPECT_THROW(CfgManifest::validate(missing), CfgTarError);

    CfgTar rebuilt;
    rebuilt.add(std::string(CfgManifest::path), "not json");
    rebuilt.add("smithproxy.cfg", "config");
    rebuilt.add("smithproxy.startup.cfg", "startup");
    EXPECT_THROW(CfgManifest::validate(rebuilt), CfgTarError);
}

TEST_F(SourceTest, RejectsWrongFormatVersionAndExtraManifestFields) {
    for (const std::string manifest : {
             R"({"format":"another-product","version":1})",
             R"({"format":"smithproxy-cftar","version":2})",
             R"({"format":"smithproxy-cftar","version":"1"})",
             R"({"format":"smithproxy-cftar","version":18446744073709551615})",
             R"({"format":"smithproxy-cftar","version":1,"extra":true})",
         }) {
        CfgTar archive;
        archive.add(std::string(CfgManifest::path), manifest);
        archive.add("smithproxy.cfg", "config");
        archive.add("smithproxy.startup.cfg", "startup");
        EXPECT_THROW(CfgManifest::validate(archive), CfgTarError) << manifest;
    }
}

TEST_F(SourceTest, RejectsOversizedManifest) {
    CfgTar archive;
    archive.add(std::string(CfgManifest::path), std::string(4097, 'x'));
    archive.add("smithproxy.cfg", "config");
    archive.add("smithproxy.startup.cfg", "startup");
    EXPECT_THROW(CfgManifest::validate(archive), CfgTarError);
}

TEST_F(SourceTest, RequiresMainAndStartupConfiguration) {
    CfgTar no_main;
    no_main.add(std::string(CfgManifest::path), CfgManifest::canonical());
    no_main.add("smithproxy.startup.cfg", "startup");
    EXPECT_THROW(CfgManifest::validate(no_main), CfgTarError);

    CfgTar no_startup;
    no_startup.add(std::string(CfgManifest::path), CfgManifest::canonical());
    no_startup.add("smithproxy.cfg", "config");
    EXPECT_THROW(CfgManifest::validate(no_startup), CfgTarError);
}

TEST_F(SourceTest, RejectsUnknownTopLevelContent) {
    auto archive = valid_archive();
    archive.add("automation/action.macro", "content");
    EXPECT_THROW(CfgManifest::validate(archive), CfgTarError);
}

TEST_F(SourceTest, UsesLegacyOnlyWhenArchiveIsAbsent) {
    std::ofstream(paths_.legacy) << "legacy";

    const auto source = CfgSource::open(paths_);

    EXPECT_EQ(source.kind(), CfgSource::Kind::legacy);
    EXPECT_EQ(source.path(), paths_.legacy);
    EXPECT_FALSE(source.is_cftar());
    EXPECT_THROW(source.archive(), CfgTarError);
}

TEST_F(SourceTest, PrefersAndExposesValidArchive) {
    std::ofstream(paths_.legacy) << "legacy";
    write_archive(valid_archive());

    const auto source = CfgSource::open(paths_);

    EXPECT_TRUE(source.is_cftar());
    EXPECT_EQ(source.path(), paths_.archive);
    EXPECT_EQ(source.main_config(), "settings : {};\n");
    EXPECT_EQ(source.startup_config(), "SMITH_RUN_TRANSPARENT=1\n");
}

TEST_F(SourceTest, ReadsValidatedArchiveFromPrivilegedBytes) {
    const auto bytes = valid_archive().write();
    const auto source = CfgSource::read_archive(paths_.archive, bytes);

    EXPECT_TRUE(source.is_cftar());
    EXPECT_EQ(source.path(), paths_.archive);
    EXPECT_EQ(source.main_config(), "settings : {};\n");
    EXPECT_THROW(CfgSource::read_archive(paths_.archive, "not an archive"), CfgTarError);
}

TEST_F(SourceTest, ResolvesPresentNativeResourceWithoutLegacyFallback) {
    auto archive = valid_archive();
    archive.add("messages/en/page.html", "native page");
    archive.add("messages/en/empty.html", "");
    write_archive(archive);
    const auto source = CfgSource::open(paths_);

    const auto page = source.resolve("messages/en/page.html", "/etc/legacy/page.html");
    EXPECT_EQ(page.kind(), CfgResource::Kind::native);
    EXPECT_TRUE(page.is_native());
    EXPECT_EQ(page.logical_path(), "messages/en/page.html");
    EXPECT_EQ(page.content(), "native page");
    EXPECT_THROW(page.legacy_path(), CfgTarError);

    // Empty is still an authoritative native value, not a fallback signal.
    EXPECT_TRUE(source.resolve("messages/en/empty.html", "/etc/legacy/empty.html")
                    .is_native());
}

TEST_F(SourceTest, ResolvesAbsentNativeResourceToExplicitLegacyPath) {
    write_archive(valid_archive());
    const auto source = CfgSource::open(paths_);

    const auto resource = source.resolve("pki/ca/default/cert.pem",
                                         "/etc/smithproxy/certs/ca/default/cert.pem");
    EXPECT_EQ(resource.kind(), CfgResource::Kind::legacy);
    EXPECT_FALSE(resource.is_native());
    EXPECT_EQ(resource.legacy_path(),
              "/etc/smithproxy/certs/ca/default/cert.pem");
    EXPECT_THROW(resource.content(), CfgTarError);
}

TEST_F(SourceTest, LegacySourceAlwaysResolvesToExplicitLegacyPath) {
    const auto source = CfgSource::open(paths_);
    const auto resource = source.resolve("ssh/host-key", "/etc/smithproxy/ssh-key");

    EXPECT_FALSE(resource.is_native());
    EXPECT_EQ(resource.legacy_path(), "/etc/smithproxy/ssh-key");
}

TEST_F(SourceTest, RejectsInvalidResourceRequestInsteadOfGuessingFallback) {
    const auto source = CfgSource::open(paths_);

    EXPECT_THROW(source.resolve("smithproxy.cfg", paths_.legacy), CfgTarError);
    EXPECT_THROW(source.resolve("pki/", paths_.legacy), CfgTarError);
    EXPECT_THROW(source.resolve("pki/cert.pem", ""), CfgTarError);
}

TEST_F(SourceTest, ListsStoredScriptsWithoutReadingOrExecutingThem) {
    auto archive = valid_archive();
    archive.add("scripts/capture-off.macro", "set capture off");
    archive.add("scripts/collect-debug.sh", "#!/bin/sh\n", true);
    archive.add("messages/en/page.html", "page");
    write_archive(archive);
    const auto source = CfgSource::open(paths_);

    EXPECT_EQ(source.resources("scripts/"),
              (std::vector<std::string>{"scripts/capture-off.macro",
                                        "scripts/collect-debug.sh"}));
    EXPECT_TRUE(source.resources("ssh/").empty());
    EXPECT_THROW(source.resources("scripts"), CfgTarError);
    EXPECT_THROW(source.resources("unknown/"), CfgTarError);
}

TEST_F(SourceTest, CompleteNativeBundleResolvesWithoutLegacyFiles) {
    auto archive = valid_archive();
    const std::vector<std::pair<std::string, std::string>> resources {
        {"messages/en/test.txt", "native message"},
        {"pki/ca/default/ca-cert.pem", "native CA"},
        {"pki/ca/default/ca-key.pem", "native CA key"},
        {"pki/ca/default/srv-cert.pem", "native server"},
        {"pki/ca/default/srv-key.pem", "native server key"},
        {"ssh/ssh_host_ed25519_key", "native SSH key"},
        {"scripts/capture-off.macro", "native macro"},
    };
    for (const auto& [path, content] : resources) archive.add(path, content);
    write_archive(archive);
    const auto source = CfgSource::open(paths_);

    for (const auto& [path, content] : resources) {
        const auto resolved = source.resolve(path, directory_ + "/does-not-exist");
        ASSERT_TRUE(resolved.is_native()) << path;
        EXPECT_EQ(resolved.content(), content) << path;
    }
}

TEST_F(SourceTest, BuildsSavePayloadWithoutLosingArchiveResources) {
    auto archive = valid_archive();
    archive.add("pki/ca/default/cert.pem", "certificate");
    write_archive(archive);
    const auto source = CfgSource::open(paths_);

    const auto saved = CfgTar::read(source.save_payload("settings : { changed = true; };\n"));

    EXPECT_EQ(saved.at("smithproxy.cfg").data, "settings : { changed = true; };\n");
    EXPECT_EQ(saved.at("pki/ca/default/cert.pem").data, "certificate");
    EXPECT_EQ(source.main_config(), "settings : {};\n");
    EXPECT_EQ(CfgTar::read(source.archive_payload()).at("smithproxy.cfg").data,
              "settings : {};\n");
}

TEST_F(SourceTest, AdvancesNativeSourceOnlyWhenSaveIsAccepted) {
    write_archive(valid_archive());
    auto source = CfgSource::open(paths_);

    const std::string changed = "settings : { changed = true; };\n";
    source.save_payload(changed);
    EXPECT_EQ(source.main_config(), "settings : {};\n");

    source.accept_saved_main(changed);
    EXPECT_EQ(source.main_config(), changed);
    EXPECT_EQ(CfgTar::read(source.archive_payload()).at("smithproxy.cfg").data, changed);
}

TEST_F(SourceTest, LegacySavePayloadIsPlainConfiguration) {
    const auto source = CfgSource::open(paths_);
    EXPECT_EQ(source.save_payload("plain config"), "plain config");
    EXPECT_THROW(source.archive_payload(), CfgTarError);
}

TEST_F(SourceTest, ExistingInvalidArchiveNeverFallsBack) {
    std::ofstream(paths_.legacy) << "legacy";
    std::ofstream(paths_.archive) << "broken archive";

    EXPECT_THROW(CfgSource::open(paths_), CfgTarError);
}

TEST_F(SourceTest, ArchiveSymlinkNeverFallsBackOrGetsFollowed) {
    std::ofstream(paths_.legacy) << "legacy";
    const auto target = directory_ + "/target.cftar";
    valid_archive().write_file(target);
    ASSERT_EQ(::symlink(target.c_str(), paths_.archive.c_str()), 0);

    EXPECT_THROW(CfgSource::open(paths_), CfgTarError);
}

TEST_F(SourceTest, ExplicitConfigOverridesExistingArchive) {
    write_archive(valid_archive());
    paths_.explicit_config = directory_ + "/manual.cfg";

    const auto source = CfgSource::open(paths_);

    EXPECT_EQ(source.kind(), CfgSource::Kind::legacy);
    EXPECT_EQ(source.path(), *paths_.explicit_config);
}

} // namespace
