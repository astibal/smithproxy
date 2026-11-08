#include <gtest/gtest.h>

#include <archive.h>
#include <archive_entry.h>

#include <service/cfgapi/cfg_tar.hpp>

#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

using sx::cfg::CfgTar;
using sx::cfg::CfgTarError;

class TempDir {
public:
    TempDir() {
        std::string pattern = "/tmp/smithproxy-cftar-test-XXXXXX";
        path_ = ::mkdtemp(pattern.data());
        if (path_.empty()) {
            throw std::runtime_error("cannot create test directory");
        }
    }
    ~TempDir() { std::filesystem::remove_all(path_); }
    const std::string& path() const noexcept { return path_; }
private:
    std::string path_;
};

la_ssize_t append_data(archive*, void* context, const void* data, size_t size) {
    static_cast<std::string*>(context)->append(static_cast<const char*>(data), size);
    return static_cast<la_ssize_t>(size);
}

struct RawEntry {
    RawEntry(std::string path_value, mode_t type_value = AE_IFREG,
             std::string data_value = {}, std::string symlink_value = {},
             std::string hardlink_value = {})
        : path(std::move(path_value)), type(type_value), data(std::move(data_value)),
          symlink(std::move(symlink_value)), hardlink(std::move(hardlink_value)) {}

    std::string path;
    mode_t type = AE_IFREG;
    std::string data;
    std::string symlink;
    std::string hardlink;
};

std::string raw_archive(const std::vector<RawEntry>& entries) {
    archive* output = archive_write_new();
    archive_write_set_format_pax_restricted(output);
    std::string bytes;
    archive_write_open(output, &bytes, nullptr, append_data, nullptr);

    for (const auto& item : entries) {
        archive_entry* entry = archive_entry_new();
        archive_entry_set_pathname(entry, item.path.c_str());
        archive_entry_set_filetype(entry, item.type);
        archive_entry_set_perm(entry, 0600);
        archive_entry_set_size(entry, static_cast<la_int64_t>(item.data.size()));
        if (!item.symlink.empty()) archive_entry_set_symlink(entry, item.symlink.c_str());
        if (!item.hardlink.empty()) archive_entry_set_hardlink(entry, item.hardlink.c_str());
        archive_write_header(output, entry);
        if (!item.data.empty()) archive_write_data(output, item.data.data(), item.data.size());
        archive_entry_free(entry);
    }
    archive_write_close(output);
    archive_write_free(output);
    return bytes;
}

std::string raw_archive(const RawEntry& entry) {
    return raw_archive(std::vector<RawEntry>{entry});
}

std::string read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

TEST(CfgTar, RoundTripIsDeterministic) {
    CfgTar archive;
    archive.add("smithproxy.cfg", "settings : {};\n");
    archive.add("scripts/health-check", "#!/bin/sh\n", true);
    archive.add("pki/trust/ca-bundle.pem", "certificate\n");

    const auto first = archive.write();
    const auto loaded = CfgTar::read(first);

    EXPECT_EQ(loaded.write(), first);
    EXPECT_EQ(loaded.at("smithproxy.cfg").data, "settings : {};\n");
    EXPECT_TRUE(loaded.at("scripts/health-check").executable);
}

TEST(CfgTar, ReadsAndWritesAFile) {
    TempDir temp;
    const auto path = temp.path() + "/config.cftar";
    CfgTar archive;
    archive.add("smithproxy.cfg", "config");

    archive.write_file(path);
    const auto loaded = CfgTar::read_file(path);

    EXPECT_EQ(loaded.at("smithproxy.cfg").data, "config");
}

TEST(CfgTar, PreservesEmptyAndBinaryFiles) {
    CfgTar archive;
    archive.add("empty", {});
    archive.add("binary", std::string("a\0b\xff", 4));

    const auto loaded = CfgTar::read(archive.write());

    EXPECT_TRUE(loaded.at("empty").data.empty());
    EXPECT_EQ(loaded.at("binary").data, std::string("a\0b\xff", 4));
}

TEST(CfgTar, SortsEntriesIndependentlyOfInsertionOrder) {
    CfgTar forward;
    forward.add("a", "1");
    forward.add("b", "2");
    CfgTar reverse;
    reverse.add("b", "2");
    reverse.add("a", "1");

    EXPECT_EQ(forward.write(), reverse.write());
}

TEST(CfgTar, ReportsMissingEntriesWithoutMutatingArchive) {
    CfgTar archive;
    archive.add("present", "value");

    EXPECT_FALSE(archive.contains("missing"));
    EXPECT_THROW(archive.at("missing"), CfgTarError);
    EXPECT_EQ(archive.entries().size(), 1U);
}

TEST(CfgTar, ReplacesOnlyExistingEntriesAndKeepsSizeAccounting) {
    CfgTar archive({4, 6, 7, 32});
    archive.add("one", "12345");
    archive.add("two", "12");

    archive.replace("one", "1", true);
    EXPECT_EQ(archive.at("one").data, "1");
    EXPECT_TRUE(archive.at("one").executable);
    EXPECT_THROW(archive.replace("missing", "x"), CfgTarError);

    archive.replace("one", "12345");
    EXPECT_THROW(archive.replace("one", "123456"), CfgTarError);
    EXPECT_EQ(archive.at("one").data, "12345");
}

TEST(CfgTar, UpsertsAndRemovesEntriesWithCorrectSizeAccounting) {
    CfgTar archive({3, 8, 8, 32});
    archive.add("one", "1234");

    archive.upsert("one", "1", true);
    archive.upsert("two", "1234567");
    EXPECT_TRUE(archive.at("one").executable);
    EXPECT_THROW(archive.upsert("three", "x"), CfgTarError);

    EXPECT_TRUE(archive.remove("two"));
    EXPECT_FALSE(archive.remove("two"));
    EXPECT_NO_THROW(archive.upsert("three", "1234567"));
}

TEST(CfgTar, RejectsUnsafePaths) {
    CfgTar archive;
    EXPECT_THROW(archive.add("/etc/passwd", "x"), CfgTarError);
    EXPECT_THROW(archive.add("pki/../passwd", "x"), CfgTarError);
    EXPECT_THROW(archive.add("pki//passwd", "x"), CfgTarError);
    EXPECT_THROW(archive.add("pki\\passwd", "x"), CfgTarError);
    EXPECT_THROW(archive.add("pki/trust\nforged", "x"), CfgTarError);
}

TEST(CfgTar, RejectsLinksAndSpecialFiles) {
    EXPECT_THROW(CfgTar::read(raw_archive({"link", AE_IFLNK, {}, "smithproxy.cfg", {}})),
                 CfgTarError);
    EXPECT_THROW(CfgTar::read(raw_archive({"copy", AE_IFREG, {}, {}, "smithproxy.cfg"})),
                 CfgTarError);
    EXPECT_THROW(CfgTar::read(raw_archive({"fifo", AE_IFIFO})), CfgTarError);
    EXPECT_THROW(CfgTar::read(raw_archive({"directory", AE_IFDIR})), CfgTarError);
    EXPECT_THROW(CfgTar::read(raw_archive({"device", AE_IFCHR})), CfgTarError);
}

TEST(CfgTar, RejectsDuplicateArchiveEntries) {
    const auto duplicate = raw_archive({{"same", AE_IFREG, "first"},
                                        {"same", AE_IFREG, "second"}});
    EXPECT_THROW(CfgTar::read(duplicate), CfgTarError);
}

TEST(CfgTar, RejectsMalformedAndTruncatedArchives) {
    EXPECT_THROW(CfgTar::read("not a tar archive"), CfgTarError);

    CfgTar archive;
    archive.add("smithproxy.cfg", std::string(4096, 'x'));
    auto truncated = archive.write();
    truncated.resize(700);
    EXPECT_THROW(CfgTar::read(truncated), CfgTarError);
}

TEST(CfgTar, EnforcesLimitsBeforeAcceptingData) {
    CfgTar::Limits limits;
    limits.max_entries = 1;
    limits.max_file_size = 4;
    limits.max_total_size = 4;
    CfgTar archive(limits);

    archive.add("one", "1234");
    EXPECT_THROW(archive.add("two", ""), CfgTarError);

    CfgTar oversized(limits);
    EXPECT_THROW(oversized.add("one", "12345"), CfgTarError);
}

TEST(CfgTar, AcceptsExactSizeAndPathLimits) {
    CfgTar::Limits limits;
    limits.max_entries = 1;
    limits.max_file_size = 4;
    limits.max_total_size = 4;
    limits.max_path_size = 4;
    CfgTar archive(limits);

    EXPECT_NO_THROW(archive.add("four", "1234"));
}

TEST(CfgTar, RejectsTotalSizeOverflowAcrossEntries) {
    CfgTar::Limits limits;
    limits.max_entries = 2;
    limits.max_file_size = 4;
    limits.max_total_size = 5;
    CfgTar archive(limits);
    archive.add("one", "1234");

    EXPECT_THROW(archive.add("two", "12"), CfgTarError);
}

TEST(CfgTar, RejectsInvalidLimitConfiguration) {
    CfgTar::Limits limits;
    limits.max_entries = 0;
    EXPECT_THROW(CfgTar archive(limits), CfgTarError);
    limits.max_entries = 1;
    limits.max_path_size = 0;
    EXPECT_THROW(CfgTar archive(limits), CfgTarError);
}

TEST(CfgTar, MaterializesPrivateFilesWithoutFollowingLinks) {
    TempDir temp;
    const auto destination = temp.path() + "/generation";
    CfgTar archive;
    archive.add("smithproxy.cfg", "config");
    archive.add("scripts/action", "script", true);

    archive.materialize(destination);

    std::ifstream config(destination + "/smithproxy.cfg");
    std::string content;
    config >> content;
    EXPECT_EQ(content, "config");

    struct stat config_stat {};
    struct stat script_stat {};
    ASSERT_EQ(::stat((destination + "/smithproxy.cfg").c_str(), &config_stat), 0);
    ASSERT_EQ(::stat((destination + "/scripts/action").c_str(), &script_stat), 0);
    EXPECT_EQ(config_stat.st_mode & 0777, 0600);
    EXPECT_EQ(script_stat.st_mode & 0777, 0700);
    EXPECT_THROW(archive.materialize(destination), CfgTarError);
}

TEST(CfgTar, RefusesDestinationSymlinkAndPreservesTarget) {
    TempDir temp;
    const auto target = temp.path() + "/target";
    const auto destination = temp.path() + "/generation";
    ASSERT_EQ(::mkdir(target.c_str(), 0700), 0);
    ASSERT_EQ(::symlink(target.c_str(), destination.c_str()), 0);
    CfgTar archive;
    archive.add("smithproxy.cfg", "new config");

    EXPECT_THROW(archive.materialize(destination), CfgTarError);
    EXPECT_FALSE(std::filesystem::exists(target + "/smithproxy.cfg"));
}

TEST(CfgTar, RefusesExistingFileAndPreservesItsContents) {
    TempDir temp;
    const auto destination = temp.path() + "/generation";
    ASSERT_EQ(::mkdir(destination.c_str(), 0700), 0);
    const auto existing = destination + "/smithproxy.cfg";
    std::ofstream(existing) << "old config";
    CfgTar archive;
    archive.add("smithproxy.cfg", "new config");

    EXPECT_THROW(archive.materialize(destination), CfgTarError);
    EXPECT_EQ(read_file(existing), "old config");
}

TEST(CfgTar, WriteFileRefusesExistingFilesAndSymlinks) {
    TempDir temp;
    const auto target = temp.path() + "/target";
    const auto link = temp.path() + "/config.cftar";
    std::ofstream(target) << "original";
    ASSERT_EQ(::symlink(target.c_str(), link.c_str()), 0);
    CfgTar archive;
    archive.add("smithproxy.cfg", "config");

    EXPECT_THROW(archive.write_file(target), CfgTarError);
    EXPECT_THROW(archive.write_file(link), CfgTarError);
    EXPECT_EQ(read_file(target), "original");
}

TEST(CfgTar, WriteFailureIsReported) {
    TempDir temp;
    const auto target = temp.path() + "/limited.cftar";
    CfgTar archive;
    archive.add("large", std::string(8192, 'x'));

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ::signal(SIGXFSZ, SIG_IGN);
        const rlimit limit{512, 512};
        if (::setrlimit(RLIMIT_FSIZE, &limit) != 0) _exit(2);
        try {
            archive.write_file(target);
        }
        catch (const CfgTarError&) {
            _exit(0);
        }
        _exit(3);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
    EXPECT_FALSE(std::filesystem::exists(target));
}

} // namespace
