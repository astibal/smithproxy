#include "cfg_pack.hpp"

#include <service/cfgapi/cfg_archive.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <filesystem>
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

// Add short, non-authoritative descriptions only for collections that are
// actually present. Runtime behavior continues to follow the logical path and
// payload; resource.json exists for administrators and generic archive tools.
void add_resource_descriptions(CfgTar& archive) {
    struct Description {
        std::string_view directory;
        std::string_view text;
    };
    constexpr std::array descriptions {
        Description{"pki/ca/default/", "Default Smithproxy certificate authority and service identities."},
        Description{"pki/trust/", "Product-managed trust anchors used for upstream certificate verification."},
        Description{"pki/mitm/ssh/hostkeys/", "SSH host keys presented by the interception service."},
        Description{"pki/mitm/tls/server/sni/", "TLS server identities selected by the intercepted SNI value."},
        Description{"pki/mitm/tls/server/ip/", "TLS server identities selected by the intercepted destination address."},
        Description{"pki/mitm/tls/client/sni/", "TLS client identities selected by the upstream SNI value."},
        Description{"pki/mitm/tls/client/ip/", "TLS client identities selected by the upstream destination address."},
        Description{"templates/replacement/", "Localized response templates presented to intercepted clients."},
        Description{"commands/macros/", "Administrative command macros stored as inert configuration resources."},
        Description{"commands/scripts/", "Administrative scripts stored as inert configuration resources."},
    };

    for(const auto& description : descriptions) {
        const bool present = std::any_of(
            archive.entries().begin(), archive.entries().end(),
            [&](const auto& item) {
                return item.first.rfind(description.directory, 0) == 0;
            });
        const std::string path = std::string(description.directory) + "resource.json";
        if(present && !archive.contains(path)) {
            archive.add(path, "{\n  \"description\": \"" +
                                  std::string(description.text) + "\"\n}\n");
        }
    }
}

} // namespace

CfgTar CfgPack::build(const Input& input) {
    if (input.main_config.empty() || input.startup_config.empty()) {
        fail("CfgTar main and startup input paths are required");
    }

    CfgTar archive;
    archive.add(std::string(CfgManifest::path), CfgManifest::canonical());
    archive.add("smithproxy.cfg", read_input(input.main_config));
    if(input.allow_missing_startup) {
        struct stat state {};
        if(::lstat(input.startup_config.c_str(), &state) == 0) {
            // read_input() keeps the ordinary regular-file and no-symlink
            // policy for an existing optional startup configuration.
            archive.add("smithproxy.startup.cfg", read_input(input.startup_config));
        }
        else if(errno == ENOENT) {
            archive.add("smithproxy.startup.cfg", "");
        }
        else {
            fail_errno("cannot inspect optional CfgTar startup input " +
                       input.startup_config);
        }
    }
    else {
        archive.add("smithproxy.startup.cfg", read_input(input.startup_config));
    }

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

    add_resource_descriptions(archive);

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

CfgPack::LegacyRetireResult CfgPack::retire_legacy_tree(
    const std::string& root,
    const std::string& active_archive,
    const std::string& backup_name) {
    namespace fs = std::filesystem;

    if(root.empty() || active_archive.empty() || backup_name.empty() ||
       active_archive.find('/') != std::string::npos ||
       backup_name.find('/') != std::string::npos) {
        fail("invalid legacy retirement path");
    }

    // Never clean around an archive that has not passed the complete native
    // format validation. The memento is a recovery aid, not a substitute for
    // a working startup configuration.
    const auto native_path = (fs::path(root) / active_archive).string();
    CfgManifest::validate(CfgTar::read_file(native_path));

    const auto backup_path = (fs::path(root) / backup_name).string();
    const auto archive_prefix = fs::path("etc/smithproxy");
    CfgTar current;
    struct LegacyFile {
        fs::path path;
        dev_t device {0};
        ino_t inode {0};
    };
    std::vector<LegacyFile> files;
    std::vector<fs::path> directories;
    std::error_code error;

    // Snapshot every remaining product-owned file. Native generations,
    // publication locks and recovery archives stay beside the active CFtar.
    for(fs::recursive_directory_iterator iterator(
            root, fs::directory_options::none, error), end;
        !error && iterator != end; iterator.increment(error)) {
        const auto relative = iterator->path().lexically_relative(root);
        const auto first = *relative.begin();
        const auto first_name = first.string();
        const bool native_sidecar = first_name == active_archive ||
            first_name == backup_name ||
            first_name.rfind(active_archive + ".", 0) == 0;
        if(native_sidecar) {
            if(iterator->is_directory(error)) iterator.disable_recursion_pending();
            error.clear();
            continue;
        }

        const auto status = iterator->symlink_status(error);
        if(error) break;
        if(fs::is_directory(status)) {
            directories.push_back(iterator->path());
            continue;
        }
        if(!fs::is_regular_file(status)) {
            fail("unsupported legacy configuration entry: " +
                 iterator->path().string());
        }

        const auto payload = read_input(iterator->path().string());
        const auto archived = (archive_prefix / relative).generic_string();
        current.add(archived, payload,
                    (status.permissions() & fs::perms::owner_exec) != fs::perms::none);
        struct stat identity {};
        if(::lstat(iterator->path().c_str(), &identity) != 0 ||
           !S_ISREG(identity.st_mode)) {
            fail("legacy configuration entry changed while scanning: " +
                 iterator->path().string());
        }
        files.push_back({iterator->path(), identity.st_dev, identity.st_ino});
    }
    if(error) {
        fail("cannot scan legacy configuration tree " + root + ": " +
             error.message());
    }
    if(files.empty()) return {};

    LegacyRetireResult result;
    CfgTar memento;
    struct stat backup_state {};
    if(::lstat(backup_path.c_str(), &backup_state) == 0) {
        if(!S_ISREG(backup_state.st_mode)) {
            fail("legacy configuration memento is not a regular file: " + backup_path);
        }
        memento = CfgTar::read_file(backup_path);
        for(const auto& [path, entry] : current.entries()) {
            if(!memento.contains(path) ||
               memento.at(path).data != entry.data ||
               memento.at(path).executable != entry.executable) {
                fail("legacy configuration changed after memento creation: " + path);
            }
        }
    }
    else if(errno == ENOENT) {
        current.write_file(backup_path);
        memento = current;
        result.backup_created = true;

        Fd parent(::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if(parent.get() < 0 || ::fsync(parent.get()) != 0) {
            fail_errno("cannot sync legacy configuration memento directory " + root);
        }
    }
    else {
        fail_errno("cannot inspect legacy configuration memento " + backup_path);
    }

    // Delete files before their directories. A partial cleanup is harmless:
    // the next start verifies every survivor against the immutable memento and
    // continues. A changed survivor stops cleanup rather than losing data.
    for(const auto& file : files) {
        const auto relative = file.path.lexically_relative(root).generic_string();
        const auto archived = (archive_prefix / relative).generic_string();
        struct stat state {};
        if(::lstat(file.path.c_str(), &state) != 0 || !S_ISREG(state.st_mode) ||
           state.st_dev != file.device || state.st_ino != file.inode) {
            fail("legacy configuration entry changed before removal: " +
                 file.path.string());
        }
        const auto& saved = memento.at(archived);
        if(read_input(file.path.string()) != saved.data ||
           ((state.st_mode & S_IXUSR) != 0) != saved.executable) {
            fail("legacy configuration changed before removal: " + file.path.string());
        }

        // Recheck identity after the potentially slow content read. This does
        // not try to outsmart a malicious root process, but it closes the
        // practical race where an administrator replaces a file during cleanup.
        struct stat before_unlink {};
        if(::lstat(file.path.c_str(), &before_unlink) != 0 ||
           before_unlink.st_dev != file.device || before_unlink.st_ino != file.inode) {
            fail("legacy configuration entry changed before removal: " +
                 file.path.string());
        }
        if(::unlink(file.path.c_str()) != 0) {
            fail_errno("cannot remove migrated legacy file " + file.path.string());
        }
        ++result.files_removed;
    }

    std::sort(directories.begin(), directories.end(),
              [](const auto& left, const auto& right) {
                  return left.native().size() > right.native().size();
              });
    for(const auto& directory : directories) {
        if(::rmdir(directory.c_str()) != 0 && errno != ENOTEMPTY) {
            fail_errno("cannot remove migrated legacy directory " + directory.string());
        }
    }

    Fd parent(::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if(parent.get() < 0 || ::fsync(parent.get()) != 0) {
        fail_errno("cannot sync retired legacy configuration directory " + root);
    }
    return result;
}

} // namespace sx::cfg
