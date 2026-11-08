#include "cfg_archive_session.hpp"

#include "cfg_archive.hpp"
#include "cfg_file_lock.hpp"

#include <utils/crypto.hpp>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <libconfig.h++>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

namespace sx::cfg {
namespace {

std::string read_regular_file(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0) {
        throw CfgTarError("cannot open " + path + ": " + std::strerror(errno));
    }

    struct stat metadata {};
    if(::fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        ::close(fd);
        throw CfgTarError("CFtar input is not a regular file: " + path);
    }
    if(static_cast<std::uint64_t>(metadata.st_size) > 256ULL * 1024ULL * 1024ULL) {
        ::close(fd);
        throw CfgTarError("CFtar input exceeds the archive size limit: " + path);
    }

    std::string result(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t offset = 0;
    while(offset < result.size()) {
        const auto count = ::read(fd, result.data() + offset, result.size() - offset);
        if(count < 0 && errno == EINTR) continue;
        if(count <= 0) {
            ::close(fd);
            throw CfgTarError("cannot read complete file " + path);
        }
        offset += static_cast<std::size_t>(count);
    }
    ::close(fd);
    return result;
}

void write_all(int fd, std::string_view bytes, const std::string& path) {
    while(!bytes.empty()) {
        const auto count = ::write(fd, bytes.data(), bytes.size());
        if(count < 0 && errno == EINTR) continue;
        if(count <= 0) {
            throw CfgTarError("cannot write " + path + ": " + std::strerror(errno));
        }
        bytes.remove_prefix(static_cast<std::size_t>(count));
    }
}

// Publish bytes through a sibling temporary file. rename(2) keeps readers on
// either the complete old file or the complete new file; fsync makes the data
// and directory entry durable before the operation reports success.
void replace_atomically(const std::string& path, std::string_view bytes) {
    struct stat existing {};
    const bool preserve_metadata = ::lstat(path.c_str(), &existing) == 0;
    if(preserve_metadata && !S_ISREG(existing.st_mode)) {
        throw CfgTarError("refusing to replace non-regular file " + path);
    }
    if(!preserve_metadata && errno != ENOENT) {
        throw CfgTarError("cannot inspect " + path + ": " + std::strerror(errno));
    }

    std::string pattern = path + ".tmp.XXXXXX";
    int fd = ::mkstemp(pattern.data());
    if(fd < 0) {
        throw CfgTarError("cannot create temporary file for " + path);
    }

    bool renamed = false;
    try {
        const auto mode = preserve_metadata ? existing.st_mode & 0777 : 0600;
        if(::fchmod(fd, mode) != 0 ||
           (preserve_metadata && ::fchown(fd, existing.st_uid, existing.st_gid) != 0)) {
            throw CfgTarError("cannot preserve metadata for " + path);
        }
        write_all(fd, bytes, pattern);
        if(::fsync(fd) != 0) {
            throw CfgTarError("cannot sync temporary file for " + path);
        }
        if(::close(fd) != 0) {
            throw CfgTarError("cannot close temporary file for " + path);
        }
        fd = -1;
        if(::rename(pattern.c_str(), path.c_str()) != 0) {
            throw CfgTarError("cannot replace " + path + ": " + std::strerror(errno));
        }
        renamed = true;

        const auto slash = path.find_last_of('/');
        const auto directory = slash == std::string::npos ? "." : path.substr(0, slash);
        const int directory_fd = ::open(
            directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if(directory_fd < 0) {
            throw CfgTarError("cannot open parent directory for " + path);
        }
        if(::fsync(directory_fd) != 0) {
            const auto detail = std::strerror(errno);
            ::close(directory_fd);
            throw CfgTarError("cannot sync parent directory for " + path + ": " + detail);
        }
        ::close(directory_fd);
    }
    catch(...) {
        if(!renamed) {
            if(fd >= 0) ::close(fd);
            ::unlink(pattern.c_str());
        }
        throw;
    }
}

std::string payload_hash(std::string_view payload) {
    const auto digest = sx::crypto::sha256(payload);
    if(!digest) throw CfgTarError("cannot hash CFtar payload");
    return "sha256:" + *digest;
}

std::string recovery_path(const std::string& archive_path) {
    return archive_path + ".previous.bak.cftar";
}

}  // namespace

CfgArchiveSession::CfgArchiveSession(
    std::string archive_path,
    std::string base_hash,
    CfgTar original)
    : archive_path_(std::move(archive_path)),
      base_hash_(std::move(base_hash)),
      original_(std::move(original)),
      working_(original_) {}

CfgArchiveSession CfgArchiveSession::open(std::string archive_path) {
    // Capture bytes and hash from the same read. save() later rechecks this
    // exact generation only after it owns the inter-process lock.
    auto payload = read_regular_file(archive_path);
    auto archive = CfgTar::read(payload);
    validate_archive(archive);
    auto hash = payload_hash(payload);
    return CfgArchiveSession(
        std::move(archive_path), std::move(hash),
        std::move(archive));
}

bool CfgArchiveSession::dirty() const {
    return working_.write() != original_.write();
}

const CfgTar::Entry& CfgArchiveSession::entry(std::string_view path) const {
    return working_.at(path);
}

void CfgArchiveSession::put(
    std::string path, std::string content, bool executable) {
    if(path == CfgManifest::path) {
        throw CfgTarError("manifest.json is managed by the CFtar format");
    }
    // Mutate a copy first. Invalid content never contaminates the working
    // generation that subsequent shell commands observe.
    auto candidate = working_;
    candidate.upsert(std::move(path), std::move(content), executable);
    validate_archive(candidate);
    working_ = std::move(candidate);
}

void CfgArchiveSession::remove(std::string_view path) {
    if(!CfgManifest::is_resource_path(path)) {
        throw CfgTarError("control file cannot be removed: " + std::string(path));
    }
    // Resource removal follows the same copy-validate-adopt rule as put().
    auto candidate = working_;
    if(!candidate.remove(path)) {
        throw CfgTarError("CfgTar entry not found: " + std::string(path));
    }
    validate_archive(candidate);
    working_ = std::move(candidate);
}

void CfgArchiveSession::discard() {
    working_ = original_;
}

void CfgArchiveSession::validate_archive(const CfgTar& archive) {
    CfgManifest::validate(archive);
    try {
        libconfig::Config parsed;
        parsed.readString(archive.at("smithproxy.cfg").data);
    }
    catch(const libconfig::ParseException& error) {
        throw CfgTarError(
            "invalid smithproxy.cfg at line " + std::to_string(error.getLine()) +
            ": " + error.getError());
    }
}

void CfgArchiveSession::validate() const {
    validate_archive(working_);
}

std::vector<CfgArchiveChange> CfgArchiveSession::changes() const {
    // Compare both directions so removals and additions are reported without
    // exposing entry contents or relying on TAR serialization order.
    std::vector<CfgArchiveChange> result;
    for(const auto& [path, entry] : original_.entries()) {
        const auto current = working_.entries().find(path);
        if(current == working_.entries().end()) {
            result.push_back({CfgArchiveChange::Kind::removed, path});
        }
        else if(current->second.data != entry.data ||
                current->second.executable != entry.executable) {
            result.push_back({CfgArchiveChange::Kind::modified, path});
        }
    }
    for(const auto& [path, entry] : working_.entries()) {
        (void)entry;
        if(original_.entries().find(path) == original_.entries().end()) {
            result.push_back({CfgArchiveChange::Kind::added, path});
        }
    }
    return result;
}

void CfgArchiveSession::save() {
    // Validation can run before the lock because the working copy is private.
    // The locked hash check is the authority for concurrent-change safety.
    validate();
    auto lock = CfgFileLock::acquire(archive_path_);
    const auto current_payload = read_regular_file(archive_path_);
    const auto current_hash = payload_hash(current_payload);
    if(current_hash != base_hash_) {
        throw CfgTarError(
            "archive changed since this session opened (expected " + base_hash_ +
            ", current " + current_hash + ")");
    }

    // Recovery must be durable before the active name moves. A failure in
    // either replacement leaves the session dirty and therefore retryable.
    const auto replacement = working_.write();
    replace_atomically(recovery_path(archive_path_), current_payload);
    replace_atomically(archive_path_, replacement);

    base_hash_ = payload_hash(replacement);
    original_ = working_;
}

}  // namespace sx::cfg
