#include <gtest/gtest.h>

#include <service/cfgapi/cfg_archive.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <string>
#include <unistd.h>

namespace {

using sx::cfg::CfgManifest;
using sx::cfg::CfgResource;
using sx::cfg::CfgArchive;
using sx::cfg::CfgTar;
using sx::cfg::CfgTarError;

class ArchiveTest : public ::testing::Test {
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
    CfgArchive::Paths paths_;
};

TEST_F(ArchiveTest, CanonicalManifestIsStable) {
    EXPECT_EQ(CfgManifest::canonical(),
              "{\n  \"format\": \"smithproxy-cftar\",\n  \"version\": 1\n}\n");
}

TEST_F(ArchiveTest, DerivesNativeSiblingsFromTheActiveLegacyPath) {
    EXPECT_EQ(CfgArchive::native_path_for("/var/lib/smithproxy/lab2.cfg"),
              "/var/lib/smithproxy/lab2.cftar");
    EXPECT_EQ(CfgArchive::startup_path_for("/var/lib/smithproxy/lab2.cfg"),
              "/var/lib/smithproxy/lab2.startup.cfg");

    EXPECT_EQ(CfgArchive::native_path_for("/var/lib/smithproxy/custom"),
              "/var/lib/smithproxy/custom.cftar");
    EXPECT_EQ(CfgArchive::startup_path_for("/var/lib/smithproxy/custom"),
              "/var/lib/smithproxy/custom.startup.cfg");
    EXPECT_THROW(CfgArchive::native_path_for(""), CfgTarError);
    EXPECT_THROW(CfgArchive::startup_path_for(""), CfgTarError);
}

TEST_F(ArchiveTest, ValidatesKnownResourceNamespaces) {
    auto archive = valid_archive();
    archive.add("pki/ca/default/ca-cert.pem", "certificate");
    archive.add("templates/replacement/en/tls-replacement.html", "message");
    archive.add("commands/scripts/disable-capture.macro", "set capture off");
    archive.add("commands/scripts/collect-debug.sh", "#!/bin/sh\n", true);
    archive.add("pki/mitm/ssh/hostkeys/ed25519", "key");

    EXPECT_NO_THROW(CfgManifest::validate(archive));
}

TEST_F(ArchiveTest, RecognizesOnlyResourceNamespaces) {
    EXPECT_TRUE(CfgManifest::is_resource_path("pki/ca/default/cert.pem"));
    EXPECT_TRUE(CfgManifest::is_resource_path("templates/replacement/en/page.html"));
    EXPECT_TRUE(CfgManifest::is_resource_path("commands/scripts/action.macro"));
    EXPECT_TRUE(CfgManifest::is_resource_path("pki/mitm/ssh/hostkeys/ed25519"));

    EXPECT_FALSE(CfgManifest::is_resource_path("pki/"));
    EXPECT_FALSE(CfgManifest::is_resource_path("smithproxy.cfg"));
    EXPECT_FALSE(CfgManifest::is_resource_path("unknown/file"));
    EXPECT_FALSE(CfgManifest::is_resource_path("pki/../host-key"));
    EXPECT_FALSE(CfgManifest::is_resource_path("templates//page.html"));
}

TEST_F(ArchiveTest, RejectsMissingOrInvalidManifest) {
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

TEST_F(ArchiveTest, RejectsWrongFormatVersionAndExtraManifestFields) {
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

TEST_F(ArchiveTest, RejectsOversizedManifest) {
    CfgTar archive;
    archive.add(std::string(CfgManifest::path), std::string(4097, 'x'));
    archive.add("smithproxy.cfg", "config");
    archive.add("smithproxy.startup.cfg", "startup");
    EXPECT_THROW(CfgManifest::validate(archive), CfgTarError);
}

TEST_F(ArchiveTest, RequiresMainAndStartupConfiguration) {
    CfgTar no_main;
    no_main.add(std::string(CfgManifest::path), CfgManifest::canonical());
    no_main.add("smithproxy.startup.cfg", "startup");
    EXPECT_THROW(CfgManifest::validate(no_main), CfgTarError);

    CfgTar no_startup;
    no_startup.add(std::string(CfgManifest::path), CfgManifest::canonical());
    no_startup.add("smithproxy.cfg", "config");
    EXPECT_THROW(CfgManifest::validate(no_startup), CfgTarError);
}

TEST_F(ArchiveTest, RejectsUnknownTopLevelContent) {
    auto archive = valid_archive();
    archive.add("automation/action.macro", "content");
    EXPECT_THROW(CfgManifest::validate(archive), CfgTarError);
}

TEST_F(ArchiveTest, UsesLegacyOnlyWhenArchiveIsAbsent) {
    std::ofstream(paths_.legacy) << "legacy";

    const auto source = CfgArchive::open(paths_);

    EXPECT_EQ(source.kind(), CfgArchive::Kind::legacy);
    EXPECT_EQ(source.path(), paths_.legacy);
    EXPECT_FALSE(source.is_cftar());
    EXPECT_THROW(source.archive(), CfgTarError);
}

TEST_F(ArchiveTest, PrefersAndExposesValidArchive) {
    std::ofstream(paths_.legacy) << "legacy";
    write_archive(valid_archive());

    const auto source = CfgArchive::open(paths_);

    EXPECT_TRUE(source.is_cftar());
    EXPECT_EQ(source.path(), paths_.archive);
    EXPECT_EQ(source.main_config(), "settings : {};\n");
    EXPECT_EQ(source.startup_config(), "SMITH_RUN_TRANSPARENT=1\n");
}

TEST_F(ArchiveTest, ReportsContentFreeNativeArchiveInventory) {
    auto archive = valid_archive();
    archive.add("commands/scripts/check.sh", "#!/bin/sh\n", true);
    write_archive(archive);
    const auto source = CfgArchive::open(paths_);

    const auto info = source.info();

    EXPECT_TRUE(info.native);
    EXPECT_EQ(info.path, paths_.archive);
    EXPECT_EQ(info.format_version, CfgManifest::version);
    ASSERT_EQ(info.entries.size(), 4U);
    const auto script = std::find_if(info.entries.begin(), info.entries.end(),
        [](const auto& entry) { return entry.path == "commands/scripts/check.sh"; });
    ASSERT_NE(script, info.entries.end());
    EXPECT_EQ(script->size, 10U);
    EXPECT_TRUE(script->executable);
    EXPECT_EQ(info.payload_size,
              std::accumulate(info.entries.begin(), info.entries.end(), std::uint64_t {0},
                  [](auto total, const auto& entry) { return total + entry.size; }));
}

TEST_F(ArchiveTest, ReportsLegacySourceWithoutArchiveEntries) {
    const auto source = CfgArchive::open(paths_);

    const auto info = source.info();

    EXPECT_FALSE(info.native);
    EXPECT_EQ(info.path, paths_.legacy);
    EXPECT_EQ(info.format_version, 0U);
    EXPECT_EQ(info.payload_size, 0U);
    EXPECT_TRUE(info.entries.empty());
}

TEST_F(ArchiveTest, ReadsValidatedArchiveFromPrivilegedBytes) {
    const auto bytes = valid_archive().write();
    const auto source = CfgArchive::read_archive(paths_.archive, bytes);

    EXPECT_TRUE(source.is_cftar());
    EXPECT_EQ(source.path(), paths_.archive);
    EXPECT_EQ(source.main_config(), "settings : {};\n");
    EXPECT_THROW(CfgArchive::read_archive(paths_.archive, "not an archive"), CfgTarError);
}

TEST_F(ArchiveTest, InspectsUploadWithoutSelectingItAsAConfigurationSource) {
    auto archive = valid_archive();
    archive.add("templates/replacement/en/page.html", "page");
    const auto bytes = archive.write();

    const auto info = CfgArchive::inspect_archive(bytes);

    EXPECT_TRUE(info.native);
    EXPECT_TRUE(info.path.empty());
    EXPECT_EQ(info.format_version, CfgManifest::version);
    EXPECT_EQ(info.entries.size(), 4U);
    EXPECT_THROW(CfgArchive::inspect_archive("not an archive"), CfgTarError);
}

TEST_F(ArchiveTest, PreparesResourceEditsWithoutMutatingSelectedSource) {
    auto archive = valid_archive();
    archive.add("templates/replacement/en/page.html", "old");
    write_archive(archive);
    auto source = CfgArchive::open(paths_);

    const auto replaced = source.prepare_resource(
        "templates/replacement/en/page.html", std::string("new"));
    EXPECT_EQ(source.resolve("templates/replacement/en/page.html", "legacy").content(), "old");
    EXPECT_EQ(CfgTar::read(replaced.replacement).at("templates/replacement/en/page.html").data, "new");
    EXPECT_EQ(replaced.previous, source.archive_payload());

    source.accept_saved_archive(replaced.replacement);
    EXPECT_EQ(source.resolve("templates/replacement/en/page.html", "legacy").content(), "new");

    const auto removed = source.prepare_resource("templates/replacement/en/page.html", std::nullopt);
    EXPECT_FALSE(CfgTar::read(removed.replacement).contains("templates/replacement/en/page.html"));
    EXPECT_THROW(source.prepare_resource("manifest.json", std::string("bad")), CfgTarError);
    EXPECT_THROW(source.prepare_resource("templates/replacement/en/missing", std::nullopt), CfgTarError);
}

TEST_F(ArchiveTest, ResolvesPresentNativeResourceWithoutLegacyFallback) {
    auto archive = valid_archive();
    archive.add("templates/replacement/en/page.html", "native page");
    archive.add("templates/replacement/en/empty.html", "");
    write_archive(archive);
    const auto source = CfgArchive::open(paths_);

    const auto page = source.resolve("templates/replacement/en/page.html", "/etc/legacy/page.html");
    EXPECT_EQ(page.kind(), CfgResource::Kind::native);
    EXPECT_TRUE(page.is_native());
    EXPECT_EQ(page.logical_path(), "templates/replacement/en/page.html");
    EXPECT_EQ(page.content(), "native page");
    EXPECT_THROW(page.legacy_path(), CfgTarError);

    // Empty is still an authoritative native value, not a fallback signal.
    EXPECT_TRUE(source.resolve("templates/replacement/en/empty.html", "/etc/legacy/empty.html")
                    .is_native());
}

TEST_F(ArchiveTest, RejectsAbsentNativeResourceWithoutLegacyFallback) {
    write_archive(valid_archive());
    const auto source = CfgArchive::open(paths_);

    EXPECT_THROW(source.resolve(
        "pki/ca/default/cert.pem",
        "/etc/smithproxy/certs/ca/default/cert.pem"), CfgTarError);
}

TEST_F(ArchiveTest, LegacySourceAlwaysResolvesToExplicitLegacyPath) {
    const auto source = CfgArchive::open(paths_);
    const auto resource = source.resolve("pki/mitm/ssh/hostkeys/ed25519", "/etc/smithproxy/ssh-key");

    EXPECT_FALSE(resource.is_native());
    EXPECT_EQ(resource.legacy_path(), "/etc/smithproxy/ssh-key");
}

TEST_F(ArchiveTest, RejectsInvalidResourceRequestInsteadOfGuessingFallback) {
    const auto source = CfgArchive::open(paths_);

    EXPECT_THROW(source.resolve("smithproxy.cfg", paths_.legacy), CfgTarError);
    EXPECT_THROW(source.resolve("pki/", paths_.legacy), CfgTarError);
    EXPECT_THROW(source.resolve("pki/cert.pem", ""), CfgTarError);
}

TEST_F(ArchiveTest, ListsStoredScriptsWithoutReadingOrExecutingThem) {
    auto archive = valid_archive();
    archive.add("commands/scripts/capture-off.macro", "set capture off");
    archive.add("commands/scripts/collect-debug.sh", "#!/bin/sh\n", true);
    archive.add("templates/replacement/en/page.html", "page");
    write_archive(archive);
    const auto source = CfgArchive::open(paths_);

    EXPECT_EQ(source.resources("commands/scripts/"),
              (std::vector<std::string>{"commands/scripts/capture-off.macro",
                                        "commands/scripts/collect-debug.sh"}));
    EXPECT_TRUE(source.resources("pki/services/").empty());
    EXPECT_THROW(source.resources("scripts"), CfgTarError);
    EXPECT_THROW(source.resources("unknown/"), CfgTarError);
}

TEST_F(ArchiveTest, CompleteNativeBundleResolvesWithoutLegacyFiles) {
    auto archive = valid_archive();
    const std::vector<std::pair<std::string, std::string>> resources {
        {"templates/replacement/en/test.txt", "native message"},
        {"pki/ca/default/ca-cert.pem", "native CA"},
        {"pki/ca/default/ca-key.pem", "native CA key"},
        {"pki/ca/default/srv-cert.pem", "native server"},
        {"pki/ca/default/srv-key.pem", "native server key"},
        {"pki/mitm/ssh/hostkeys/ed25519", "native SSH key"},
        {"commands/scripts/capture-off.macro", "native macro"},
    };
    for (const auto& [path, content] : resources) archive.add(path, content);
    write_archive(archive);
    const auto source = CfgArchive::open(paths_);

    for (const auto& [path, content] : resources) {
        const auto resolved = source.resolve(path, directory_ + "/does-not-exist");
        ASSERT_TRUE(resolved.is_native()) << path;
        EXPECT_EQ(resolved.content(), content) << path;
    }
}

TEST_F(ArchiveTest, BuildsSavePayloadWithoutLosingArchiveResources) {
    auto archive = valid_archive();
    archive.add("pki/ca/default/cert.pem", "certificate");
    write_archive(archive);
    const auto source = CfgArchive::open(paths_);

    const auto save = source.prepare_save("settings : { changed = true; };\n");
    const auto saved = CfgTar::read(save.replacement);

    EXPECT_EQ(saved.at("smithproxy.cfg").data, "settings : { changed = true; };\n");
    EXPECT_EQ(saved.at("pki/ca/default/cert.pem").data, "certificate");
    ASSERT_TRUE(save.previous);
    const auto previous = CfgTar::read(*save.previous);
    EXPECT_EQ(previous.at("smithproxy.cfg").data, "settings : {};\n");
    EXPECT_EQ(previous.at("pki/ca/default/cert.pem").data, "certificate");
    EXPECT_EQ(source.main_config(), "settings : {};\n");
    EXPECT_EQ(CfgTar::read(source.archive_payload()).at("smithproxy.cfg").data,
              "settings : {};\n");
}

TEST_F(ArchiveTest, AdvancesNativeSourceOnlyWhenSaveIsAccepted) {
    write_archive(valid_archive());
    auto source = CfgArchive::open(paths_);

    const std::string changed = "settings : { changed = true; };\n";
    source.prepare_save(changed);
    EXPECT_EQ(source.main_config(), "settings : {};\n");

    source.accept_saved_main(changed);
    EXPECT_EQ(source.main_config(), changed);
    EXPECT_EQ(CfgTar::read(source.archive_payload()).at("smithproxy.cfg").data, changed);
}

TEST_F(ArchiveTest, LegacySavePayloadIsPlainConfiguration) {
    const auto source = CfgArchive::open(paths_);
    const auto save = source.prepare_save("plain config");
    EXPECT_EQ(save.replacement, "plain config");
    EXPECT_FALSE(save.previous);
    EXPECT_THROW(source.archive_payload(), CfgTarError);
}

TEST_F(ArchiveTest, ExistingInvalidArchiveNeverFallsBack) {
    std::ofstream(paths_.legacy) << "legacy";
    std::ofstream(paths_.archive) << "broken archive";

    EXPECT_THROW(CfgArchive::open(paths_), CfgTarError);
}

TEST_F(ArchiveTest, ArchiveSymlinkNeverFallsBackOrGetsFollowed) {
    std::ofstream(paths_.legacy) << "legacy";
    const auto target = directory_ + "/target.cftar";
    valid_archive().write_file(target);
    ASSERT_EQ(::symlink(target.c_str(), paths_.archive.c_str()), 0);

    EXPECT_THROW(CfgArchive::open(paths_), CfgTarError);
}

TEST_F(ArchiveTest, ExplicitConfigOverridesExistingArchive) {
    write_archive(valid_archive());
    paths_.explicit_config = directory_ + "/manual.cfg";

    const auto source = CfgArchive::open(paths_);

    EXPECT_EQ(source.kind(), CfgArchive::Kind::legacy);
    EXPECT_EQ(source.path(), *paths_.explicit_config);
}

TEST_F(ArchiveTest, ExplicitArchiveIsValidatedAndSelected) {
    const auto manual_archive = directory_ + "/manual.cftar";
    valid_archive().write_file(manual_archive);
    paths_.explicit_archive = manual_archive;

    const auto source = CfgArchive::open(paths_);

    EXPECT_EQ(source.kind(), CfgArchive::Kind::cftar);
    EXPECT_EQ(source.path(), manual_archive);
    EXPECT_EQ(source.main_config(), "settings : {};\n");
}

TEST_F(ArchiveTest, InvalidExplicitArchiveNeverFallsBack) {
    const auto manual_archive = directory_ + "/manual.cftar";
    std::ofstream(manual_archive) << "broken archive";
    std::ofstream(paths_.legacy) << "legacy";
    paths_.explicit_archive = manual_archive;

    EXPECT_THROW(CfgArchive::open(paths_), CfgTarError);
}

} // namespace
