#include "cfg_pack.hpp"

#include <service/cfgapi/cfg_source.hpp>

#include <cerrno>
#include <cstring>
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
    if (file.get() < 0) {
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
        archive.add(file.archive_path, read_input(file.source_path), file.executable);
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
