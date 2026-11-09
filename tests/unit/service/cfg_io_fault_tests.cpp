#include <gtest/gtest.h>

#include <archive.h>
#include <archive_entry.h>

#include <service/cfgapi/cfg_archive.hpp>
#include <service/cfgapi/cfg_pack.hpp>
#include <service/cfgapi/cfg_tar.hpp>

#include <cstdarg>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

enum class Fault {
    none,
    open,
    openat,
    fstat,
    fstatat,
    lstat,
    read_error,
    read_eintr,
    read_eof,
    read_growth,
    write_error,
    write_eintr,
    write_zero,
    fsync,
    dup,
    fdopendir,
    readdir,
    mkdir,
    mkdirat,
    archive_read_new,
    archive_read_support,
    archive_read_open,
    archive_next_header,
    archive_entry_path,
    archive_read_data_error,
    archive_read_data_eof,
    archive_write_new,
    archive_write_format,
    archive_write_open,
    archive_entry_new,
    archive_write_header,
    archive_write_data,
    archive_write_close,
};

struct FaultState {
    Fault fault = Fault::none;
    std::size_t target = 1;
    std::size_t calls = 0;

    bool hit(Fault operation) {
        if(fault != operation) return false;
        return ++calls == target;
    }
};

FaultState fault_state;

class ScopedFault {
public:
    explicit ScopedFault(Fault fault, std::size_t target = 1) {
        fault_state = {fault, target, 0};
    }
    ~ScopedFault() { fault_state = {}; }
};

class TempDir {
public:
    TempDir() {
        std::string pattern = "/tmp/smithproxy-cfg-io-fault-XXXXXX";
        path_ = ::mkdtemp(pattern.data());
        if(path_.empty()) throw std::runtime_error("cannot create test directory");
    }
    ~TempDir() { std::filesystem::remove_all(path_); }

    std::string write(const std::string& name, const std::string& data) const {
        const auto path = path_ + "/" + name;
        std::ofstream(path, std::ios::binary) << data;
        return path;
    }

    const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
};

sx::cfg::CfgTar archive_with_file() {
    sx::cfg::CfgTar archive;
    archive.add("smithproxy.cfg", "settings : {};\n");
    return archive;
}

sx::cfg::CfgPack::Input pack_input(const TempDir& temp) {
    sx::cfg::CfgPack::Input input;
    input.main_config = temp.write("smithproxy.cfg", "settings : {};\n");
    input.startup_config = temp.write(
        "smithproxy.startup.cfg", "SMITH_RUN_TRANSPARENT=1\n");
    return input;
}

}  // namespace

extern "C" {

int __real_open(const char*, int, ...);
int __wrap_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if(flags & O_CREAT) {
        va_list arguments;
        va_start(arguments, flags);
        mode = static_cast<mode_t>(va_arg(arguments, int));
        va_end(arguments);
    }
    if(fault_state.hit(Fault::open)) {
        errno = EIO;
        return -1;
    }
    return flags & O_CREAT ? __real_open(path, flags, mode)
                           : __real_open(path, flags);
}

int __real_openat(int, const char*, int, ...);
int __wrap_openat(int parent, const char* path, int flags, ...) {
    mode_t mode = 0;
    if(flags & O_CREAT) {
        va_list arguments;
        va_start(arguments, flags);
        mode = static_cast<mode_t>(va_arg(arguments, int));
        va_end(arguments);
    }
    if(fault_state.hit(Fault::openat)) {
        errno = EIO;
        return -1;
    }
    return flags & O_CREAT ? __real_openat(parent, path, flags, mode)
                           : __real_openat(parent, path, flags);
}

int __real_fstat(int, struct stat*);
int __wrap_fstat(int fd, struct stat* state) {
    if(fault_state.hit(Fault::fstat)) {
        errno = EIO;
        return -1;
    }
    return __real_fstat(fd, state);
}

int __real_fstatat(int, const char*, struct stat*, int);
int __wrap_fstatat(int fd, const char* path, struct stat* state, int flags) {
    if(fault_state.hit(Fault::fstatat)) {
        errno = EIO;
        return -1;
    }
    return __real_fstatat(fd, path, state, flags);
}

int __real_lstat(const char*, struct stat*);
int __wrap_lstat(const char* path, struct stat* state) {
    if(fault_state.hit(Fault::lstat)) {
        errno = EACCES;
        return -1;
    }
    return __real_lstat(path, state);
}

ssize_t __real_read(int, void*, size_t);
ssize_t __wrap_read(int fd, void* data, size_t size) {
    if(fault_state.hit(Fault::read_error)) {
        errno = EIO;
        return -1;
    }
    if(fault_state.hit(Fault::read_eintr)) {
        errno = EINTR;
        return -1;
    }
    if(fault_state.hit(Fault::read_eof)) return 0;
    if(fault_state.hit(Fault::read_growth)) {
        static_cast<char*>(data)[0] = 'x';
        return 1;
    }
    return __real_read(fd, data, size);
}

ssize_t __real_write(int, const void*, size_t);
ssize_t __wrap_write(int fd, const void* data, size_t size) {
    if(fault_state.hit(Fault::write_error)) {
        errno = EIO;
        return -1;
    }
    if(fault_state.hit(Fault::write_eintr)) {
        errno = EINTR;
        return -1;
    }
    if(fault_state.hit(Fault::write_zero)) return 0;
    return __real_write(fd, data, size);
}

int __real_fsync(int);
int __wrap_fsync(int fd) {
    if(fault_state.hit(Fault::fsync)) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

int __real_dup(int);
int __wrap_dup(int fd) {
    if(fault_state.hit(Fault::dup)) {
        errno = EMFILE;
        return -1;
    }
    return __real_dup(fd);
}

DIR* __real_fdopendir(int);
DIR* __wrap_fdopendir(int fd) {
    if(fault_state.hit(Fault::fdopendir)) {
        errno = EMFILE;
        return nullptr;
    }
    return __real_fdopendir(fd);
}

dirent* __real_readdir(DIR*);
dirent* __wrap_readdir(DIR* directory) {
    if(fault_state.hit(Fault::readdir)) {
        errno = EIO;
        return nullptr;
    }
    return __real_readdir(directory);
}

int __real_mkdir(const char*, mode_t);
int __wrap_mkdir(const char* path, mode_t mode) {
    if(fault_state.hit(Fault::mkdir)) {
        errno = EIO;
        return -1;
    }
    return __real_mkdir(path, mode);
}

int __real_mkdirat(int, const char*, mode_t);
int __wrap_mkdirat(int parent, const char* path, mode_t mode) {
    if(fault_state.hit(Fault::mkdirat)) {
        errno = EIO;
        return -1;
    }
    return __real_mkdirat(parent, path, mode);
}

archive* __real_archive_read_new();
archive* __wrap_archive_read_new() {
    if(fault_state.hit(Fault::archive_read_new)) return nullptr;
    return __real_archive_read_new();
}

int __real_archive_read_support_format_tar(archive*);
int __wrap_archive_read_support_format_tar(archive* input) {
    if(fault_state.hit(Fault::archive_read_support)) return ARCHIVE_FATAL;
    return __real_archive_read_support_format_tar(input);
}

int __real_archive_read_open_memory(archive*, const void*, size_t);
int __wrap_archive_read_open_memory(archive* input, const void* data, size_t size) {
    if(fault_state.hit(Fault::archive_read_open)) return ARCHIVE_FATAL;
    return __real_archive_read_open_memory(input, data, size);
}

int __real_archive_read_next_header(archive*, archive_entry**);
int __wrap_archive_read_next_header(archive* input, archive_entry** entry) {
    if(fault_state.hit(Fault::archive_next_header)) return ARCHIVE_FATAL;
    return __real_archive_read_next_header(input, entry);
}

int __real_archive_errno(archive*);
int __wrap_archive_errno(archive* input) {
    if(fault_state.fault == Fault::archive_next_header &&
       fault_state.calls >= fault_state.target) return EIO;
    return __real_archive_errno(input);
}

const char* __real_archive_entry_pathname(archive_entry*);
const char* __wrap_archive_entry_pathname(archive_entry* entry) {
    if(fault_state.hit(Fault::archive_entry_path)) return nullptr;
    return __real_archive_entry_pathname(entry);
}

la_ssize_t __real_archive_read_data(archive*, void*, size_t);
la_ssize_t __wrap_archive_read_data(archive* input, void* data, size_t size) {
    if(fault_state.hit(Fault::archive_read_data_error)) return -1;
    if(fault_state.hit(Fault::archive_read_data_eof)) return 0;
    return __real_archive_read_data(input, data, size);
}

archive* __real_archive_write_new();
archive* __wrap_archive_write_new() {
    if(fault_state.hit(Fault::archive_write_new)) return nullptr;
    return __real_archive_write_new();
}

int __real_archive_write_set_format_pax_restricted(archive*);
int __wrap_archive_write_set_format_pax_restricted(archive* output) {
    if(fault_state.hit(Fault::archive_write_format)) return ARCHIVE_FATAL;
    return __real_archive_write_set_format_pax_restricted(output);
}

int __real_archive_write_open(
    archive*, void*, archive_open_callback*, archive_write_callback*,
    archive_close_callback*);
int __wrap_archive_write_open(
    archive* output, void* context, archive_open_callback* open_callback,
    archive_write_callback* write_callback, archive_close_callback* close_callback) {
    if(fault_state.hit(Fault::archive_write_open)) return ARCHIVE_FATAL;
    return __real_archive_write_open(
        output, context, open_callback, write_callback, close_callback);
}

archive_entry* __real_archive_entry_new();
archive_entry* __wrap_archive_entry_new() {
    if(fault_state.hit(Fault::archive_entry_new)) return nullptr;
    return __real_archive_entry_new();
}

int __real_archive_write_header(archive*, archive_entry*);
int __wrap_archive_write_header(archive* output, archive_entry* entry) {
    if(fault_state.hit(Fault::archive_write_header)) return ARCHIVE_FATAL;
    return __real_archive_write_header(output, entry);
}

la_ssize_t __real_archive_write_data(archive*, const void*, size_t);
la_ssize_t __wrap_archive_write_data(archive* output, const void* data, size_t size) {
    if(fault_state.hit(Fault::archive_write_data)) return -1;
    return __real_archive_write_data(output, data, size);
}

int __real_archive_write_close(archive*);
int __wrap_archive_write_close(archive* output) {
    if(fault_state.hit(Fault::archive_write_close)) return ARCHIVE_FATAL;
    return __real_archive_write_close(output);
}

}  // extern "C"

TEST(CfgTarFaults, ReportsArchiveReaderSetupFailures) {
    for(const auto failure : {Fault::archive_read_new,
                              Fault::archive_read_support,
                              Fault::archive_read_open}) {
        SCOPED_TRACE(static_cast<int>(failure));
        ScopedFault fault(failure);
        EXPECT_THROW(sx::cfg::CfgTar::read("invalid"), sx::cfg::CfgTarError);
    }
}

TEST(CfgTarFaults, ReportsArchiveEntryReadFailures) {
    const auto bytes = archive_with_file().write();
    for(const auto failure : {Fault::archive_next_header,
                              Fault::archive_entry_path,
                              Fault::archive_read_data_error,
                              Fault::archive_read_data_eof}) {
        SCOPED_TRACE(static_cast<int>(failure));
        ScopedFault fault(failure);
        EXPECT_THROW(sx::cfg::CfgTar::read(bytes), sx::cfg::CfgTarError);
    }
}

TEST(CfgTarFaults, ReportsOpenedArchiveInspectionFailure) {
    TempDir temp;
    const auto path = temp.path() + "/archive.cftar";
    archive_with_file().write_file(path);
    ScopedFault fault(Fault::fstat);

    EXPECT_THROW(sx::cfg::CfgTar::read_file(path), sx::cfg::CfgTarError);
}

TEST(CfgTarFaults, ReportsArchiveWriterFailures) {
    const auto archive = archive_with_file();
    for(const auto failure : {Fault::archive_write_new,
                              Fault::archive_write_format,
                              Fault::archive_write_open,
                              Fault::archive_entry_new,
                              Fault::archive_write_header,
                              Fault::archive_write_data,
                              Fault::archive_write_close}) {
        SCOPED_TRACE(static_cast<int>(failure));
        ScopedFault fault(failure);
        EXPECT_THROW(archive.write(), sx::cfg::CfgTarError);
    }
}

TEST(CfgTarFaults, RetriesInterruptedWriteAndReportsTerminalWriteFailures) {
    TempDir temp;
    const auto archive = archive_with_file();

    {
        ScopedFault fault(Fault::write_eintr);
        EXPECT_NO_THROW(archive.write_file(temp.path() + "/interrupted.cftar"));
    }
    for(const auto failure : {Fault::write_error, Fault::write_zero}) {
        SCOPED_TRACE(static_cast<int>(failure));
        const auto path = temp.path() + "/failed-" +
                          std::to_string(static_cast<int>(failure)) + ".cftar";
        ScopedFault fault(failure);
        EXPECT_THROW(archive.write_file(path), sx::cfg::CfgTarError);
        EXPECT_FALSE(std::filesystem::exists(path));
    }
}

TEST(CfgTarFaults, ReportsFileAndDirectorySyncFailures) {
    TempDir temp;
    const auto archive = archive_with_file();
    {
        ScopedFault fault(Fault::fsync);
        EXPECT_THROW(
            archive.write_file(temp.path() + "/unsynced.cftar"),
            sx::cfg::CfgTarError);
    }
    {
        ScopedFault fault(Fault::fsync);
        EXPECT_THROW(
            archive.materialize(temp.path() + "/unsynced-tree"),
            sx::cfg::CfgTarError);
    }
    {
        ScopedFault fault(Fault::fsync, 2);
        EXPECT_THROW(
            archive.materialize(temp.path() + "/unsynced-directory"),
            sx::cfg::CfgTarError);
    }
}

TEST(CfgTarFaults, ReportsMaterializationSyscallFailures) {
    const std::vector<std::pair<Fault, std::size_t>> failures {
        {Fault::mkdir, 1},
        {Fault::open, 1},
        {Fault::dup, 1},
        {Fault::mkdirat, 1},
        {Fault::openat, 1},
    };
    for(const auto [failure, call] : failures) {
        SCOPED_TRACE(static_cast<int>(failure));
        TempDir temp;
        auto archive = archive_with_file();
        archive.add("nested/resource", "data");
        ScopedFault fault(failure, call);
        EXPECT_THROW(
            archive.materialize(temp.path() + "/generation"),
            sx::cfg::CfgTarError);
    }
}

TEST(CfgTarFaults, ReportsFinalEntryCreationFailure) {
    TempDir temp;
    auto archive = archive_with_file();
    archive.add("nested/resource", "data");
    // openat #1 enters "nested"; #2 creates its final resource.
    ScopedFault fault(Fault::openat, 2);

    EXPECT_THROW(
        archive.materialize(temp.path() + "/generation"),
        sx::cfg::CfgTarError);
}

TEST(CfgPackFaults, ReportsMainInputInspectionAndReadFailures) {
    for(const auto failure : {Fault::fstat, Fault::read_error,
                              Fault::read_eof}) {
        SCOPED_TRACE(static_cast<int>(failure));
        TempDir temp;
        const auto input = pack_input(temp);
        ScopedFault fault(failure);
        EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
    }
}

TEST(CfgPackFaults, RetriesInterruptedMainInputReads) {
    TempDir temp;
    const auto input = pack_input(temp);
    ScopedFault fault(Fault::read_eintr);

    EXPECT_NO_THROW(sx::cfg::CfgPack::build(input));
}

TEST(CfgPackFaults, RejectsInputGrowthAfterInspection) {
    TempDir temp;
    const auto input = pack_input(temp);
    // The first read copies main configuration; the second is the one-byte
    // growth probe performed after the inspected size has been consumed.
    ScopedFault fault(Fault::read_growth, 2);

    EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
}

TEST(CfgPackFaults, HandlesExtraProbeInterruptAndError) {
    {
        TempDir temp;
        const auto input = pack_input(temp);
        ScopedFault fault(Fault::read_eintr, 2);
        EXPECT_NO_THROW(sx::cfg::CfgPack::build(input));
    }
    {
        TempDir temp;
        const auto input = pack_input(temp);
        ScopedFault fault(Fault::read_error, 2);
        EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
    }
}

TEST(CfgPackFaults, ReportsOpenedDirectoryFileReadFailures) {
    struct Scenario {
        Fault fault;
        std::size_t call;
    };
    const std::vector<Scenario> scenarios {
        {Fault::fstat, 3},
        {Fault::read_eintr, 5},
        {Fault::read_eof, 5},
        {Fault::read_growth, 6},
    };
    for(const auto scenario : scenarios) {
        SCOPED_TRACE(static_cast<int>(scenario.fault));
        TempDir temp;
        auto input = pack_input(temp);
        const auto resources = temp.path() + "/resources";
        ASSERT_TRUE(std::filesystem::create_directories(resources));
        std::ofstream(resources + "/item") << "data";
        input.directories.push_back({"templates/replacement/en", resources});
        ScopedFault fault(scenario.fault, scenario.call);

        if(scenario.fault == Fault::read_eintr) {
            EXPECT_NO_THROW(sx::cfg::CfgPack::build(input));
        }
        else {
            EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
        }
    }
}

TEST(CfgPackFaults, RejectsOversizedOpenedDirectoryFile) {
    TempDir temp;
    auto input = pack_input(temp);
    const auto resources = temp.path() + "/resources";
    ASSERT_TRUE(std::filesystem::create_directories(resources));
    const auto oversized = resources + "/oversized";
    const int fd = ::open(oversized.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::ftruncate(fd, 64LL * 1024LL * 1024LL + 1), 0);
    ASSERT_EQ(::close(fd), 0);
    input.directories.push_back({"templates/replacement/en", resources});

    EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
}

TEST(CfgPackFaults, ReportsNestedDirectoryOpenFailure) {
    TempDir temp;
    auto input = pack_input(temp);
    const auto resources = temp.path() + "/resources";
    ASSERT_TRUE(std::filesystem::create_directories(resources + "/nested"));
    input.directories.push_back({"templates/replacement/en", resources});
    ScopedFault fault(Fault::openat);

    EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
}

TEST(CfgPackFaults, ReportsDirectoryTraversalFailures) {
    const std::vector<Fault> failures {
        Fault::dup,
        Fault::fdopendir,
        Fault::fstatat,
        Fault::openat,
        Fault::readdir,
    };
    for(const auto failure : failures) {
        SCOPED_TRACE(static_cast<int>(failure));
        TempDir temp;
        auto input = pack_input(temp);
        const auto resources = temp.path() + "/resources";
        ASSERT_TRUE(std::filesystem::create_directories(resources));
        std::ofstream(resources + "/item") << "data";
        input.directories.push_back({"templates/replacement/en", resources});
        ScopedFault fault(failure);
        EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
    }
}

TEST(CfgPackFaults, ReportsOptionalInputInspectionFailures) {
    TempDir temp;
    auto input = pack_input(temp);
    input.files.push_back({
        "templates/replacement/en/optional", temp.path() + "/optional", false, true});
    {
        ScopedFault fault(Fault::lstat);
        EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
    }

    input.files.clear();
    input.directories.push_back({
        "templates/replacement/en", temp.path() + "/optional-directory", true});
    {
        ScopedFault fault(Fault::lstat);
        EXPECT_THROW(sx::cfg::CfgPack::build(input), sx::cfg::CfgTarError);
    }
}
