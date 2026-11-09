#pragma once

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sx::atomic_json {

namespace detail {
[[noreturn]] inline void fail(char const* operation) {
    throw std::system_error(errno ? errno : EIO, std::generic_category(), operation);
}

struct fd_owner {
    int fd;
    ~fd_owner() { if (fd >= 0) ::close(fd); }
};

struct temporary_file {
    std::string path;
    ~temporary_file() { if (!path.empty()) ::unlink(path.c_str()); }
};

struct file_closer {
    void operator()(FILE* file) const { std::fclose(file); }
};
} // namespace detail

inline void write(FILE* file, std::string_view text) {
    if (std::fwrite(text.data(), 1, text.size(), file) != text.size())
        detail::fail("write JSON snapshot");
}

// The writer must leave the stream open. No operation before rename changes
// the destination. The temporary file is on the same filesystem and private
// until it has been completely written and verified.
template<class Writer>
void replace(std::string const& destination, Writer&& writer) {
    auto parent = std::filesystem::path(destination).parent_path();
    if (parent.empty()) parent = ".";
    detail::fd_owner directory{::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (directory.fd < 0) detail::fail("open JSON snapshot directory");

    struct stat previous{};
    bool existing = ::lstat(destination.c_str(), &previous) == 0;
    if (!existing && errno != ENOENT) detail::fail("stat JSON snapshot destination");
    if (existing && !S_ISREG(previous.st_mode))
        throw std::runtime_error("JSON snapshot destination is not a regular file");

    std::string pattern = destination + ".tmp.XXXXXX";
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back('\0');
    detail::fd_owner fd{::mkstemp(name.data())};
    if (fd.fd < 0) detail::fail("create JSON snapshot temporary file");
    detail::temporary_file temporary{std::string(name.data())};
    if (::fcntl(fd.fd, F_SETFD, FD_CLOEXEC) < 0)
        detail::fail("set JSON snapshot close-on-exec");

    std::unique_ptr<FILE, detail::file_closer> file(::fdopen(fd.fd, "w"));
    if (!file) detail::fail("open JSON snapshot stream");
    fd.fd = -1; // FILE now owns the descriptor.
    writer(file.get());
    if (std::ferror(file.get()) || std::fflush(file.get()) != 0)
        detail::fail("flush JSON snapshot");

    // Read the bytes actually written, not the in-memory serialization. accept
    // validates one complete JSON document without rebuilding the entire DOM.
    {
        std::ifstream input(temporary.path, std::ios::binary);
        if (!input) throw std::runtime_error("cannot reopen JSON snapshot for validation");
        input.exceptions(std::ios::badbit);
        if (!nlohmann::json::accept(input))
            throw std::runtime_error("JSON snapshot integrity check failed");
    }

    if (existing) {
        struct stat created{};
        if (::fstat(::fileno(file.get()), &created) != 0)
            detail::fail("stat JSON snapshot temporary file");
        if ((created.st_uid != previous.st_uid || created.st_gid != previous.st_gid) &&
            ::fchown(::fileno(file.get()), previous.st_uid, previous.st_gid) != 0)
            detail::fail("preserve JSON snapshot ownership");
        if (::fchmod(::fileno(file.get()), previous.st_mode & 0777) != 0)
            detail::fail("preserve JSON snapshot permissions");
    }
    if (::fsync(::fileno(file.get())) != 0) detail::fail("sync JSON snapshot");
    if (std::fclose(file.release()) != 0) detail::fail("close JSON snapshot");
    if (::rename(temporary.path.c_str(), destination.c_str()) != 0)
        detail::fail("rename JSON snapshot");
    temporary.path.clear();
    // A failure here is after publication: the new file is valid, but survival
    // of a crash cannot be guaranteed. Do not claim the old file was retained.
    if (::fsync(directory.fd) != 0)
        detail::fail("JSON snapshot replaced, but directory sync failed");
}

} // namespace sx::atomic_json
