#include "cfg_archive_session.hpp"

#include "cfg_archive.hpp"
#include "cfg_file_lock.hpp"

#include <utils/crypto.hpp>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <libconfig.h++>
#include <limits>

namespace sx::cfg {
namespace {

std::string read_regular_file(const CfgIo& io, const std::string& path) {
    const int fd = io.open_read(path);
    if(fd < 0) {
        throw CfgTarError("cannot open " + path + ": " + std::strerror(errno));
    }

    struct stat metadata {};
    if(io.inspect_open(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        io.close(fd);
        throw CfgTarError("CFtar input is not a regular file: " + path);
    }
    if(static_cast<std::uint64_t>(metadata.st_size) > 256ULL * 1024ULL * 1024ULL) {
        io.close(fd);
        throw CfgTarError("CFtar input exceeds the archive size limit: " + path);
    }

    std::string result(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t offset = 0;
    while(offset < result.size()) {
        const auto count = io.read(fd, result.data() + offset, result.size() - offset);
        if(count < 0 && errno == EINTR) continue;
        if(count <= 0) {
            io.close(fd);
            throw CfgTarError("cannot read complete file " + path);
        }
        offset += static_cast<std::size_t>(count);
    }
    if(io.close(fd) != 0) {
        throw CfgTarError("cannot close " + path + ": " + std::strerror(errno));
    }
    return result;
}

void write_all(const CfgIo& io, int fd, std::string_view bytes, const std::string& path) {
    while(!bytes.empty()) {
        const auto count = io.write(fd, bytes.data(), bytes.size());
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
void replace_atomically(const CfgIo& io, const std::string& path, std::string_view bytes) {
    struct stat existing {};
    const bool preserve_metadata = io.inspect_path(path, &existing) == 0;
    if(preserve_metadata && !S_ISREG(existing.st_mode)) {
        throw CfgTarError("refusing to replace non-regular file " + path);
    }
    if(!preserve_metadata && errno != ENOENT) {
        throw CfgTarError("cannot inspect " + path + ": " + std::strerror(errno));
    }

    std::string pattern = path + ".tmp.XXXXXX";
    int fd = io.create_temp(pattern);
    if(fd < 0) {
        throw CfgTarError("cannot create temporary file for " + path);
    }

    bool renamed = false;
    try {
        const auto mode = preserve_metadata ? existing.st_mode & 0777 : 0600;
        if(io.set_mode(fd, mode) != 0 ||
           (preserve_metadata && io.set_owner(fd, existing.st_uid, existing.st_gid) != 0)) {
            throw CfgTarError("cannot preserve metadata for " + path);
        }
        write_all(io, fd, bytes, pattern);
        if(io.sync(fd) != 0) {
            throw CfgTarError("cannot sync temporary file for " + path);
        }
        // close(2) may report an error after consuming the descriptor. Never
        // retry the same numeric descriptor, which another thread could reuse.
        const auto completed_fd = fd;
        fd = -1;
        if(io.close(completed_fd) != 0) {
            throw CfgTarError("cannot close temporary file for " + path);
        }
        if(io.replace(pattern, path) != 0) {
            throw CfgTarError("cannot replace " + path + ": " + std::strerror(errno));
        }
        renamed = true;

        const auto slash = path.find_last_of('/');
        const auto directory = slash == std::string::npos ? "." : path.substr(0, slash);
        const int directory_fd = io.open_directory(directory);
        if(directory_fd < 0) {
            throw CfgTarError("cannot open parent directory for " + path);
        }
        if(io.sync(directory_fd) != 0) {
            const auto detail = std::strerror(errno);
            io.close(directory_fd);
            throw CfgTarError("cannot sync parent directory for " + path + ": " + detail);
        }
        if(io.close(directory_fd) != 0) {
            throw CfgTarError("cannot close parent directory for " + path);
        }
    }
    catch(...) {
        if(!renamed) {
            if(fd >= 0) io.close(fd);
            io.remove(pattern);
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
    CfgTar original,
    CfgIoPtr io)
    : archive_path_(std::move(archive_path)),
      base_hash_(std::move(base_hash)),
      original_(std::move(original)),
      working_(original_),
      io_(std::move(io)) {}

CfgArchiveSession CfgArchiveSession::open(std::string archive_path) {
    return open(std::move(archive_path), std::make_shared<CfgIo>());
}

CfgArchiveSession CfgArchiveSession::open(std::string archive_path, CfgIoPtr io) {
    if(!io) throw CfgTarError("CFtar I/O provider is not available");
    // Capture bytes and hash from the same read. save() later rechecks this
    // exact generation only after it owns the inter-process lock.
    auto payload = read_regular_file(*io, archive_path);
    auto archive = CfgTar::read(payload);
    validate_archive(archive);
    auto hash = payload_hash(payload);
    return CfgArchiveSession(
        std::move(archive_path), std::move(hash),
        std::move(archive), std::move(io));
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
    auto lock = CfgFileLock::acquire(
        archive_path_, std::chrono::seconds(5), io_);
    const auto current_payload = read_regular_file(*io_, archive_path_);
    const auto current_hash = payload_hash(current_payload);
    if(current_hash != base_hash_) {
        throw CfgTarError(
            "archive changed since this session opened (expected " + base_hash_ +
            ", current " + current_hash + ")");
    }

    // Recovery must be durable before the active name moves. A failure in
    // either replacement leaves the session dirty and therefore retryable.
    const auto replacement = working_.write();
    const auto recovery = recovery_path(archive_path_);
    replace_atomically(*io_, recovery, current_payload);

    // Recovery publication can be arbitrarily slow on a busy device. A
    // non-cooperating administrator may replace the active archive while the
    // process still owns its advisory lock, so verify the source generation
    // again immediately before publishing the candidate.
    const auto pre_publish_payload = read_regular_file(*io_, archive_path_);
    const auto pre_publish_hash = payload_hash(pre_publish_payload);
    if(pre_publish_hash != base_hash_) {
        throw CfgTarError(
            "archive changed while this session was saving (expected " +
            base_hash_ + ", current " + pre_publish_hash + ")");
    }

    // Do not publish a generation after an external actor removed or replaced
    // its recovery copy. This check deliberately happens after the active
    // archive check so both prerequisites are adjacent to the final rename.
    const auto recovery_payload = read_regular_file(*io_, recovery);
    const auto recovery_hash = payload_hash(recovery_payload);
    if(recovery_hash != base_hash_) {
        throw CfgTarError(
            "CFtar recovery changed while this session was saving (expected " +
            base_hash_ + ", current " + recovery_hash + ")");
    }
    replace_atomically(*io_, archive_path_, replacement);

    base_hash_ = payload_hash(replacement);
    original_ = working_;
}

}  // namespace sx::cfg
