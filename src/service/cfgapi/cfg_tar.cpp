#include "cfg_tar.hpp"

#include <archive.h>
#include <archive_entry.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace sx::cfg {
namespace {

using ArchiveReadPtr = std::unique_ptr<archive, decltype(&archive_read_free)>;
using ArchiveWritePtr = std::unique_ptr<archive, decltype(&archive_write_free)>;
using ArchiveEntryPtr = std::unique_ptr<archive_entry, decltype(&archive_entry_free)>;

[[noreturn]] void fail(const std::string& message) {
    throw CfgTarError(message);
}

[[noreturn]] void fail_errno(const std::string& action) {
    fail(action + ": " + std::strerror(errno));
}

std::string archive_error(struct archive* handle, const std::string& action) {
    const char* detail = archive_error_string(handle);
    return action + (detail ? ": " + std::string(detail) : std::string{});
}

void write_all(int fd, std::string_view data, const std::string& path) {
    // write(2) may complete only part of the request or be interrupted. Keep
    // the retry policy here so archive files and materialized files behave alike.
    while (!data.empty()) {
        const auto written = ::write(fd, data.data(), data.size());
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            fail_errno("cannot write " + path);
        }
        if (written == 0) {
            fail("cannot write " + path + ": write made no progress");
        }
        data.remove_prefix(static_cast<std::size_t>(written));
    }
}

// Small local RAII wrapper. File descriptors must not leak through any of the
// validation and I/O exceptions below.
class Fd final {
public:
    explicit Fd(int value = -1) noexcept : value_(value) {}
    ~Fd() { if (value_ >= 0) ::close(value_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(other.release()) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            if (value_ >= 0) ::close(value_);
            value_ = other.release();
        }
        return *this;
    }
    int get() const noexcept { return value_; }
    int release() noexcept {
        const int result = value_;
        value_ = -1;
        return result;
    }
private:
    int value_;
};

// write_file() promises not to leave a plausible-looking truncated archive.
// The caller explicitly keeps the path only after data and metadata are durable.
class NewFileGuard final {
public:
    explicit NewFileGuard(std::string path) : path_(std::move(path)) {}
    ~NewFileGuard() {
        if (!keep_) ::unlink(path_.c_str());
    }
    NewFileGuard(const NewFileGuard&) = delete;
    NewFileGuard& operator=(const NewFileGuard&) = delete;
    void keep() noexcept { keep_ = true; }
private:
    std::string path_;
    bool keep_ = false;
};

int open_child_dir(int parent, std::string_view name, const std::string& full_path) {
    const std::string component(name);
    if (::mkdirat(parent, component.c_str(), 0700) < 0 && errno != EEXIST) {
        fail_errno("cannot create " + full_path);
    }

    // Re-open every component relative to the already verified parent. This
    // prevents a path component from redirecting extraction through a symlink.
    const int fd = ::openat(parent, component.c_str(),
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        fail_errno("cannot open " + full_path);
    }
    return fd;
}

void materialize_entry(int root_fd, const std::string& root_path,
                       const std::string& path, const CfgTar::Entry& entry) {
    // Work exclusively from the trusted root descriptor. String paths below
    // are used for diagnostics; filesystem traversal uses openat/mkdirat.
    Fd current(::dup(root_fd));
    if (current.get() < 0) {
        fail_errno("cannot duplicate destination descriptor");
    }

    std::size_t start = 0;
    while (true) {
        const auto slash = path.find('/', start);
        if (slash == std::string::npos) {
            break;
        }

        const auto component = std::string_view(path).substr(start, slash - start);
        const std::string full_path = root_path + "/" + path.substr(0, slash);
        current = Fd(open_child_dir(current.get(), component, full_path));
        start = slash + 1;
    }

    const std::string leaf = path.substr(start);
    const std::string full_path = root_path + "/" + path;
    // O_EXCL prevents silent merging with another generation. O_NOFOLLOW is
    // defense in depth for the final component after validating all parents.
    const int flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC;
    Fd output(::openat(current.get(), leaf.c_str(), flags, entry.executable ? 0700 : 0600));
    if (output.get() < 0) {
        fail_errno("cannot create " + full_path);
    }

    write_all(output.get(), entry.data, full_path);
    if (::fsync(output.get()) < 0) {
        fail_errno("cannot sync " + full_path);
    }
}

la_ssize_t append_archive(struct archive*, void* context, const void* data, size_t size) {
    // libarchive streams output through callbacks. Keeping bytes in memory
    // separates deterministic serialization from filesystem activation.
    auto& output = *static_cast<std::string*>(context);
    output.append(static_cast<const char*>(data), size);
    return static_cast<la_ssize_t>(size);
}

CfgTar read_opened_archive(struct archive* input, CfgTar::Limits limits) {
    CfgTar result(limits);
    archive_entry* raw_entry = nullptr;

    while (archive_read_next_header(input, &raw_entry) == ARCHIVE_OK) {
        const char* raw_path = archive_entry_pathname(raw_entry);
        if (!raw_path) {
            fail("CfgTar entry has no path");
        }
        const std::string path(raw_path);

        // CfgTar carries files only. Directories are inferred from their paths;
        // links and sparse files would make materialization ambiguous or unsafe.
        if (archive_entry_filetype(raw_entry) != AE_IFREG ||
            archive_entry_symlink(raw_entry) || archive_entry_hardlink(raw_entry) ||
            archive_entry_sparse_count(raw_entry) != 0) {
            fail("unsupported CfgTar entry type: " + path);
        }

        // Check the declared size before allocating. add() performs the total
        // archive limit and duplicate-path checks after the payload is read.
        const auto declared_size = archive_entry_size(raw_entry);
        if (declared_size < 0 || static_cast<std::uint64_t>(declared_size) > limits.max_file_size) {
            fail("invalid CfgTar entry size: " + path);
        }

        // A short payload is corruption, not an implicitly zero-padded file.
        std::string data(static_cast<std::size_t>(declared_size), '\0');
        std::size_t offset = 0;
        while (offset < data.size()) {
            const auto count = archive_read_data(input, data.data() + offset, data.size() - offset);
            if (count < 0) {
                fail(archive_error(input, "cannot read CfgTar entry " + path));
            }
            if (count == 0) {
                fail("truncated CfgTar entry: " + path);
            }
            offset += static_cast<std::size_t>(count);
        }

        result.add(path, std::move(data), (archive_entry_perm(raw_entry) & 0111) != 0);
    }

    if (archive_errno(input) != 0) {
        fail(archive_error(input, "cannot read CfgTar"));
    }
    return result;
}

} // namespace

CfgTar::CfgTar() : CfgTar(Limits{}) {}

CfgTar::CfgTar(Limits limits) : limits_(limits) {
    if (limits_.max_entries == 0 || limits_.max_path_size == 0) {
        fail("CfgTar limits must be greater than zero");
    }
}

std::string CfgTar::checked_path(std::string_view path, const Limits& limits) {
    // The normalized form is intentionally strict. There is exactly one
    // spelling for every member and no platform-specific separator.
    if (path.empty() || path.size() > limits.max_path_size) {
        fail("invalid CfgTar path length");
    }
    if (path.front() == '/' || path.back() == '/' || path.find('\\') != path.npos) {
        fail("unsafe CfgTar path: " + std::string(path));
    }
    for (const unsigned char character : path) {
        if (character < 0x20 || character == 0x7f) {
            fail("control character in CfgTar path");
        }
    }

    // Validate each component separately so '.', '..' and empty components
    // can never acquire filesystem meaning during materialization.
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto end = path.find('/', start);
        const auto component = path.substr(start, end - start);
        if (component.empty() || component == "." || component == "..") {
            fail("unsafe CfgTar path: " + std::string(path));
        }
        if (end == path.npos) {
            break;
        }
        start = end + 1;
    }
    return std::string(path);
}

void CfgTar::check_size(std::size_t size) const {
    if (size > limits_.max_file_size) {
        fail("CfgTar entry exceeds the per-file size limit");
    }
    // Subtraction avoids overflowing total_size_ + size on hostile input.
    if (size > limits_.max_total_size - total_size_) {
        fail("CfgTar exceeds the total size limit");
    }
}

void CfgTar::add(std::string path, std::string data, bool executable) {
    // All construction paths converge here. A parsed archive therefore cannot
    // bypass the same path, duplicate, count and aggregate-size policy used by
    // archives assembled inside Smithproxy.
    path = checked_path(path, limits_);
    check_size(data.size());
    if (entries_.size() >= limits_.max_entries) {
        fail("CfgTar contains too many entries");
    }

    const auto [position, inserted] = entries_.emplace(
        std::move(path), Entry{std::move(data), executable});
    if (!inserted) {
        fail("duplicate CfgTar entry: " + position->first);
    }
    total_size_ += position->second.data.size();
}

// Replace the data and executable flag of an entry that is already present.
// The map key and entry count stay unchanged. Size limits are evaluated as if
// the old data had first been removed, and a rejected replacement leaves both
// the entry and aggregate-size accounting untouched.
void CfgTar::replace(std::string_view path, std::string data, bool executable) {
    const auto checked = checked_path(path, limits_);
    const auto position = entries_.find(checked);
    if (position == entries_.end()) {
        fail("cannot replace missing CfgTar path: " + checked);
    }

    // Temporarily remove the previous size so check_size() evaluates the
    // prospective archive. Restore the accounting if validation fails.
    const auto previous_size = static_cast<std::uint64_t>(position->second.data.size());
    total_size_ -= previous_size;
    try {
        check_size(data.size());
    }
    catch (...) {
        total_size_ += previous_size;
        throw;
    }

    position->second = Entry{std::move(data), executable};
    total_size_ += static_cast<std::uint64_t>(position->second.data.size());
}

void CfgTar::upsert(std::string path, std::string data, bool executable) {
    const auto checked = checked_path(path, limits_);
    if(entries_.find(checked) == entries_.end()) {
        add(std::move(path), std::move(data), executable);
        return;
    }
    replace(checked, std::move(data), executable);
}

bool CfgTar::remove(std::string_view path) {
    const auto checked = checked_path(path, limits_);
    const auto position = entries_.find(checked);
    if(position == entries_.end()) return false;

    total_size_ -= static_cast<std::uint64_t>(position->second.data.size());
    entries_.erase(position);
    return true;
}

bool CfgTar::contains(std::string_view path) const {
    return entries_.find(std::string(path)) != entries_.end();
}

const CfgTar::Entry& CfgTar::at(std::string_view path) const {
    const auto found = entries_.find(std::string(path));
    if (found == entries_.end()) {
        fail("CfgTar entry not found: " + std::string(path));
    }
    return found->second;
}

const CfgTar::Entries& CfgTar::entries() const noexcept {
    return entries_;
}

CfgTar CfgTar::read_file(const std::string& path) {
    return read_file(path, Limits{});
}

CfgTar CfgTar::read_file(const std::string& path, Limits limits) {
    Fd file(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (file.get() < 0) {
        fail_errno("cannot open CfgTar " + path);
    }
    struct stat state {};
    if (::fstat(file.get(), &state) != 0) {
        fail_errno("cannot open CfgTar " + path);
    }
    if (!S_ISREG(state.st_mode)) {
        fail("CfgTar is not a regular file: " + path);
    }

    // Keep the descriptor alive until after libarchive releases its reader.
    // Local destruction order is reversed, hence the reader is declared last.
    ArchiveReadPtr input(archive_read_new(), archive_read_free);
    // Enable only the TAR format. In particular, do not enable libarchive's
    // decompression filters: .cftar is deliberately an uncompressed format.
    if (!input || archive_read_support_format_tar(input.get()) != ARCHIVE_OK ||
        archive_read_open_fd(input.get(), file.get(), 64 * 1024) != ARCHIVE_OK) {
        fail(input ? archive_error(input.get(), "cannot open CfgTar") : "cannot allocate archive reader");
    }

    return read_opened_archive(input.get(), limits);
}

CfgTar CfgTar::read(std::string_view bytes) {
    return read(bytes, Limits{});
}

CfgTar CfgTar::read(std::string_view bytes, Limits limits) {
    ArchiveReadPtr input(archive_read_new(), archive_read_free);
    if (!input || archive_read_support_format_tar(input.get()) != ARCHIVE_OK ||
        archive_read_open_memory(input.get(), bytes.data(), bytes.size()) != ARCHIVE_OK) {
        fail(input ? archive_error(input.get(), "cannot open CfgTar") : "cannot allocate archive reader");
    }

    return read_opened_archive(input.get(), limits);
}

std::string CfgTar::write() const {
    ArchiveWritePtr output(archive_write_new(), archive_write_free);
    if (!output || archive_write_set_format_pax_restricted(output.get()) != ARCHIVE_OK) {
        fail(output ? archive_error(output.get(), "cannot configure CfgTar writer")
                    : "cannot allocate archive writer");
    }

    std::string bytes;
    if (archive_write_open(output.get(), &bytes, nullptr, append_archive, nullptr) != ARCHIVE_OK) {
        fail(archive_error(output.get(), "cannot open CfgTar writer"));
    }

    // Entries is a std::map, so archive order is stable. Volatile ownership and
    // timestamps are fixed as well; the same logical archive yields same bytes.
    for (const auto& [path, entry] : entries_) {
        ArchiveEntryPtr header(archive_entry_new(), archive_entry_free);
        if (!header) fail("cannot allocate CfgTar entry");
        archive_entry_set_pathname(header.get(), path.c_str());
        archive_entry_set_filetype(header.get(), AE_IFREG);
        archive_entry_set_perm(header.get(), entry.executable ? 0700 : 0600);
        archive_entry_set_uid(header.get(), 0);
        archive_entry_set_gid(header.get(), 0);
        archive_entry_set_mtime(header.get(), 0, 0);
        archive_entry_set_size(header.get(), static_cast<la_int64_t>(entry.data.size()));

        if (archive_write_header(output.get(), header.get()) != ARCHIVE_OK ||
            archive_write_data(output.get(), entry.data.data(), entry.data.size()) !=
                static_cast<la_ssize_t>(entry.data.size())) {
            fail(archive_error(output.get(), "cannot write CfgTar entry " + path));
        }
    }

    if (archive_write_close(output.get()) != ARCHIVE_OK) {
        fail(archive_error(output.get(), "cannot finish CfgTar"));
    }
    return bytes;
}

void CfgTar::write_file(const std::string& path) const {
    const auto bytes = write();
    // Atomic activation belongs to the generation layer. This primitive only
    // creates a fresh private file and never overwrites an existing archive.
    Fd output(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (output.get() < 0) {
        fail_errno("cannot create " + path);
    }
    NewFileGuard cleanup(path);
    write_all(output.get(), bytes, path);
    if (::fsync(output.get()) < 0) {
        fail_errno("cannot sync " + path);
    }
    cleanup.keep();
}

void CfgTar::materialize(const std::string& destination) const {
    // A generation is assembled in a brand-new 0700 directory. Requiring a new
    // path makes accidental overlay of old configuration impossible.
    if (::mkdir(destination.c_str(), 0700) < 0) {
        fail_errno("cannot create " + destination);
    }
    Fd root(::open(destination.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (root.get() < 0) {
        fail_errno("cannot open " + destination);
    }

    for (const auto& [path, entry] : entries_) {
        materialize_entry(root.get(), destination, path, entry);
    }
    if (::fsync(root.get()) < 0) {
        fail_errno("cannot sync " + destination);
    }
}

} // namespace sx::cfg
