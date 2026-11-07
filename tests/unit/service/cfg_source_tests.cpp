#include <gtest/gtest.h>

#include <service/cfgapi/cfg_source.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace {

using sx::cfg::CfgManifest;
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
