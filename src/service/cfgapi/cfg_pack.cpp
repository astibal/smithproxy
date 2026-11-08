#include "cfg_pack.hpp"

#include <service/cfgapi/cfg_archive.hpp>

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sx::cfg {
namespace {

constexpr std::size_t max_input_size = 64ULL * 1024ULL * 1024ULL;

// Own a source descriptor until all bytes have been copied into the archive.
class Fd {
public:
    explicit Fd(int value) noexcept : value_(value) {}
    ~Fd() {
        if (value_ >= 0) {
            ::close(value_);
        }
    }

    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    int get() const noexcept { return value_; }

private:
    int value_;
};

class DirectoryHandle {
public:
    explicit DirectoryHandle(DIR* value) noexcept : value_(value) {}
    ~DirectoryHandle() {
        if(value_) {
            ::closedir(value_);
        }
    }

    DirectoryHandle(const DirectoryHandle&) = delete;
    DirectoryHandle& operator=(const DirectoryHandle&) = delete;

    DIR* get() const noexcept { return value_; }

private:
    DIR* value_ = nullptr;
};

[[noreturn]] void fail(const std::string& message) {
    throw CfgTarError(message);
}

[[noreturn]] void fail_errno(const std::string& message) {
    fail(message + ": " + std::strerror(errno));
}

// Read a stable regular file without following a final symlink. The size is
// bounded before allocation and checked again while reading, which turns a
// concurrent truncate or growth into a migration failure instead of a partial
// archive entry.
std::string read_input(const std::string& path) {
    Fd file(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if(file.get() < 0) {
        fail_errno("cannot open CfgTar input " + path);
    }

    struct stat state {};
    if (::fstat(file.get(), &state) != 0) {
        fail_errno("cannot inspect CfgTar input " + path);
    }
    if (!S_ISREG(state.st_mode)) {
        fail("CfgTar input is not a regular file: " + path);
    }
    if (state.st_size < 0 || static_cast<std::uint64_t>(state.st_size) > max_input_size) {
        fail("CfgTar input exceeds its size limit: " + path);
    }

    std::string data(static_cast<std::size_t>(state.st_size), '\0');
    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto count = ::read(file.get(), data.data() + offset, data.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            fail(count == 0 ? "CfgTar input changed while reading: " + path
                            : "cannot read CfgTar input " + path + ": " + std::strerror(errno));
        }
        offset += static_cast<std::size_t>(count);
    }

    char extra = 0;
    while (true) {
        const auto count = ::read(file.get(), &extra, 1);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            fail_errno("cannot read CfgTar input " + path);
        }
        if (count > 0) {
            fail("CfgTar input changed while reading: " + path);
        }
        break;
    }

    return data;
}

std::string read_open_input(int descriptor, const std::string& display_path) {
    Fd file(descriptor);
    if(file.get() < 0) {
        fail_errno("cannot open CfgTar input " + display_path);
    }

    struct stat state {};
    if(::fstat(file.get(), &state) != 0 || !S_ISREG(state.st_mode)) {
        fail("CfgTar input is not a regular file: " + display_path);
    }
    if(state.st_size < 0 || static_cast<std::uint64_t>(state.st_size) > max_input_size) {
        fail("CfgTar input exceeds its size limit: " + display_path);
    }

    std::string data(static_cast<std::size_t>(state.st_size), '\0');
    std::size_t offset = 0;
    while(offset < data.size()) {
        const auto count = ::read(file.get(), data.data() + offset, data.size() - offset);
        if(count < 0 && errno == EINTR) {
            continue;
        }
        if(count <= 0) {
            fail("CfgTar input changed while reading: " + display_path);
        }
        offset += static_cast<std::size_t>(count);
    }

    // A byte beyond the inspected size means the source changed during the
    // copy. Reject the complete migration rather than archive mixed state.
    char extra = 0;
    if(::read(file.get(), &extra, 1) != 0) {
        fail("CfgTar input changed while reading: " + display_path);
    }
    return data;
}

// Traverse through directory descriptors. Neither the root nor a nested
// component can be redirected through a symlink between inspection and open.
void add_directory(CfgTar& archive, int root, const std::string& source,
                   const std::string& prefix) {
    const int duplicate = ::dup(root);
    if(duplicate < 0) {
        fail_errno("cannot inspect CfgTar directory " + source);
    }
    DIR* raw = ::fdopendir(duplicate);
    if(!raw) {
        ::close(duplicate);
        fail_errno("cannot inspect CfgTar directory " + source);
    }
    DirectoryHandle directory(raw);

    errno = 0;
    while(auto* entry = ::readdir(directory.get())) {
        const std::string name(entry->d_name);
        if(name == "." || name == "..") {
            continue;
        }

        struct stat state {};
        if(::fstatat(root, name.c_str(), &state, AT_SYMLINK_NOFOLLOW) != 0) {
            fail_errno("cannot inspect CfgTar directory entry " + source + "/" + name);
        }
        const auto archive_path = prefix + "/" + name;
        const auto display_path = source + "/" + name;
        if(S_ISREG(state.st_mode)) {
            const int file = ::openat(root, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            archive.add(archive_path, read_open_input(file, display_path),
                        (state.st_mode & S_IXUSR) != 0);
        }
        else if(S_ISDIR(state.st_mode)) {
            Fd child(::openat(root, name.c_str(),
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if(child.get() < 0) {
                fail_errno("cannot open CfgTar directory " + display_path);
            }
            add_directory(archive, child.get(), display_path, archive_path);
        }
        else {
            fail("unsupported CfgTar directory entry: " + display_path);
        }
        errno = 0;
    }
    if(errno != 0) {
        fail_errno("cannot read CfgTar directory " + source);
    }
}

bool absent_optional_input(const CfgPack::File& file) {
    if (!file.optional) return false;
    struct stat state {};
    if (::lstat(file.source_path.c_str(), &state) == 0) return false;
    if (errno == ENOENT) return true;
    fail_errno("cannot inspect optional CfgTar input " + file.source_path);
}

bool absent_optional_directory(const CfgPack::Directory& directory) {
    if(!directory.optional) return false;
    struct stat state {};
    if(::lstat(directory.source_path.c_str(), &state) == 0) return false;
    if(errno == ENOENT) return true;
    fail_errno("cannot inspect optional CfgTar directory " + directory.source_path);
}

} // namespace

CfgTar CfgPack::build(const Input& input) {
    if (input.main_config.empty() || input.startup_config.empty()) {
        fail("CfgTar main and startup input paths are required");
    }

    CfgTar archive;
    archive.add(std::string(CfgManifest::path), CfgManifest::canonical());
    archive.add("smithproxy.cfg", read_input(input.main_config));
    archive.add("smithproxy.startup.cfg", read_input(input.startup_config));

    // Extra resources are intentionally explicit. The caller owns legacy path
    // mapping; CfgManifest owns which native archive paths are acceptable.
    for (const auto& file : input.files) {
        if (file.source_path.empty()) {
            fail("CfgTar resource source path is required");
        }
        if (absent_optional_input(file)) continue;
        archive.add(file.archive_path, read_input(file.source_path), file.executable);
    }

    // A directory input represents one closed resource subtree. Traversal is
    // descriptor-relative, so a concurrent symlink swap cannot escape it.
    for(const auto& directory : input.directories) {
        if(directory.source_path.empty() || directory.archive_prefix.empty()) {
            fail("CfgTar directory source and archive prefix are required");
        }
        if(absent_optional_directory(directory)) continue;
        Fd root(::open(directory.source_path.c_str(),
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if(root.get() < 0) {
            fail_errno("cannot open CfgTar directory " + directory.source_path);
        }
        add_directory(archive, root.get(), directory.source_path,
                      directory.archive_prefix);
    }

    CfgManifest::validate(archive);
    return archive;
}

bool CfgPack::migrate(const Migration& migration) {
    if (migration.archive_path.empty()) {
        fail("CfgTar migration output path is required");
    }

    try {
        build(migration.input).write_file(migration.archive_path);
        return true;
    }
    catch (const CfgTarError&) {
        // A destination that appeared after source selection must never be
        // replaced. Validate it before accepting the concurrent migration.
        struct stat state {};
        if (::lstat(migration.archive_path.c_str(), &state) == 0) {
            if (!S_ISREG(state.st_mode)) {
                throw;
            }
            auto archive = CfgTar::read_file(migration.archive_path);
            CfgManifest::validate(archive);
            return false;
        }
        throw;
    }
}

} // namespace sx::cfg
