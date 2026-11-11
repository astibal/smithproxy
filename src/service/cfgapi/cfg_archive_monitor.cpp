#include "cfg_archive_monitor.hpp"

#include "cfg_archive.hpp"
#include "cfg_log.hpp"

#include <service/privileged_file.hpp>
#include <utils/crypto.hpp>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/stat.h>

namespace sx::cfg {
namespace {

constexpr unsigned metadata_fast_path_limit = 29;

// Use the same digest representation as archive download and transaction APIs.
std::string payload_hash(std::string_view payload) {
    const auto digest = sx::crypto::sha256(payload);
    if(!digest) throw CfgTarError("cannot hash configuration archive");
    return "sha256:" + *digest;
}

}  // namespace

CfgArchiveMonitor::CfgArchiveMonitor(Context context)
    : path_(std::move(context.path)),
      read_archive_(context.read_archive
          ? std::move(context.read_archive)
          : [](const std::string& path, std::string& payload) {
                return sx::privsep::files::config_read(path, payload);
            }),
      accepted_hash_(payload_hash(context.accepted_payload)) {
    if(path_.empty()) throw CfgTarError("archive monitor path is empty");
    config_log().inf("configuration archive monitor initialized");
}

bool CfgArchiveMonitor::FileSignature::operator==(
    const FileSignature& other) const noexcept {
    return device == other.device && inode == other.inode && size == other.size &&
           modified_seconds == other.modified_seconds &&
           modified_nanoseconds == other.modified_nanoseconds;
}

CfgArchiveMonitor::FileSignature CfgArchiveMonitor::signature() const {
    struct stat state {};
    if(::lstat(path_.c_str(), &state) != 0) {
        throw CfgTarError(
            "cannot stat configuration archive: " + std::string(std::strerror(errno)));
    }
    if(!S_ISREG(state.st_mode)) {
        throw CfgTarError("configuration archive is not a regular file");
    }
    return {
        state.st_dev,
        state.st_ino,
        static_cast<std::uint64_t>(state.st_size),
        static_cast<std::int64_t>(state.st_mtim.tv_sec),
        static_cast<std::int64_t>(state.st_mtim.tv_nsec),
    };
}

sx::reload::ReloadResult CfgArchiveMonitor::poll() {
    return check(false);
}

sx::reload::ReloadResult CfgArchiveMonitor::reload_now() {
    return check(true);
}

void CfgArchiveMonitor::accept(std::string_view payload) {
    const auto hash = payload_hash(payload);
    std::lock_guard lock(state_lock_);
    accepted_hash_ = hash;
    detected_hash_.clear();
    last_error_.clear();
    have_attempted_signature_ = false;
    metadata_fast_paths_remaining_ = 0;
    change_detected_.store(false, std::memory_order_release);
    config_log().dia("configuration archive monitor accepted internal publication");
}

bool CfgArchiveMonitor::change_detected() const noexcept {
    return change_detected_.load(std::memory_order_acquire);
}

std::string CfgArchiveMonitor::detected_hash() const {
    std::lock_guard lock(state_lock_);
    return detected_hash_;
}

std::string CfgArchiveMonitor::last_error() const {
    std::lock_guard lock(state_lock_);
    return last_error_;
}

sx::reload::ReloadResult CfgArchiveMonitor::fail(std::string detail) {
    config_log().err("configuration archive monitor failed: %s", detail.c_str());
    std::lock_guard lock(state_lock_);
    detected_hash_.clear();
    last_error_ = std::move(detail);
    change_detected_.store(true, std::memory_order_release);
    return {sx::reload::ReloadStatus::failed, version_.load(), last_error_};
}

sx::reload::ReloadResult CfgArchiveMonitor::check(bool force) {
    FileSignature before;
    try {
        before = signature();
    }
    catch(const std::exception& error) {
        return fail(error.what());
    }

    {
        std::lock_guard lock(state_lock_);
        if(!force && have_attempted_signature_ && attempted_signature_ == before &&
           metadata_fast_paths_remaining_ > 0) {
            --metadata_fast_paths_remaining_;
            // A cached invalid generation remains a failure until the bytes
            // change or an accepted internal publication replaces it. Do not
            // downgrade a persistent archive error to an "unchanged" success.
            if(!last_error_.empty()) {
                return {
                    sx::reload::ReloadStatus::failed,
                    version_.load(),
                    last_error_,
                };
            }
            return {sx::reload::ReloadStatus::unchanged, version_.load(), {}};
        }
        attempted_signature_ = before;
        have_attempted_signature_ = true;
        metadata_fast_paths_remaining_ = metadata_fast_path_limit;
    }

    // Read through the privilege-separation facade. It uses the direct path in
    // isolated tests and the fixed privileged capability after identity drop.
    std::string payload;
    if(read_archive_(path_, payload) != 0) {
        return fail(
            "cannot read configuration archive: " + std::string(std::strerror(errno)));
    }

    try {
        const auto after = signature();
        if(!(before == after)) {
            std::lock_guard lock(state_lock_);
            have_attempted_signature_ = false;
            throw CfgTarError("configuration archive changed while it was being read");
        }

        const auto hash = payload_hash(payload);
        {
            std::lock_guard lock(state_lock_);
            if(hash == accepted_hash_) {
                detected_hash_.clear();
                last_error_.clear();
                change_detected_.store(false, std::memory_order_release);
                return {sx::reload::ReloadStatus::unchanged, version_.load(), {}};
            }
        }

        // Validation is diagnostic only. Even an invalid external replacement
        // is a persistent-state change and must prevent ordinary saves.
        CfgArchive::inspect_archive(payload);

        const auto next_version = version_.fetch_add(1, std::memory_order_acq_rel) + 1;
        {
            std::lock_guard lock(state_lock_);
            detected_hash_ = hash;
            last_error_.clear();
            change_detected_.store(true, std::memory_order_release);
        }
        config_log().noti("external configuration archive change detected: version=%llu",
                          static_cast<unsigned long long>(next_version));
        return {sx::reload::ReloadStatus::published, next_version, {}};
    }
    catch(const std::exception& error) {
        return fail(error.what());
    }
}

}  // namespace sx::cfg
