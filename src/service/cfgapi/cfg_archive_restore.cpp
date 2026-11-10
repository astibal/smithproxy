#include "cfg_archive_restore.hpp"

#include "cfg_archive.hpp"
#include "cfg_log.hpp"

#include <utils/crypto.hpp>

#include <utility>

namespace sx::cfg {

CfgArchiveRestorer::CfgArchiveRestorer(Context context): context_(std::move(context)) {}

ArchiveRestoreResult CfgArchiveRestorer::restore(
    const std::string& expected_revision,
    const std::string& expected_hash,
    const std::string& payload) {
    config_log().noti("configuration archive restore requested: bytes=%zu", payload.size());
    // Validate before taking the global gate: parsing a large upload must not
    // unnecessarily block ordinary configuration writers.
    std::string hash;
    try {
        CfgArchive::inspect_archive(payload);

        // Bind restore to the exact bytes accepted by the validation request.
        auto digest = sx::crypto::sha256(payload);
        if(!digest) throw CfgTarError("cannot hash configuration archive");
        hash = "sha256:" + *digest;
    }
    catch(const std::exception& error) {
        config_log().war("configuration archive restore rejected: %s", error.what());
        return {ArchiveRestoreStatus::invalid_archive, {}, {}, error.what()};
    }

    if(hash != expected_hash) {
        config_log().war("configuration archive restore rejected: validated hash mismatch");
        return {ArchiveRestoreStatus::hash_mismatch, {}, std::move(hash),
                "uploaded archive does not match the validated content hash"};
    }

    // The guard keeps revision checks and archive publication in one critical
    // section shared with CLI, GUI transactions and explicit save.
    auto guard = context_.gate.enter(context_.config_mutex);
    if(!guard) {
        config_log().war("configuration archive restore rejected: write lease is busy");
        return {ArchiveRestoreStatus::lease_busy, context_.board.revision_state(), hash, {}};
    }

    // Configuration may have changed while the archive was being validated.
    // Re-read revision only after the write gate is owned.
    const auto revision = context_.board.revision_state();
    if(revision.current_id != expected_revision) {
        config_log().war("configuration archive restore rejected: expected revision is stale");
        return {ArchiveRestoreStatus::stale_revision, revision, hash, {}};
    }
    if(revision.unsaved) {
        config_log().war("configuration archive restore rejected: running configuration is unsaved");
        return {ArchiveRestoreStatus::unsaved_running, revision, hash, {}};
    }

    // A legacy text file cannot provide the complete backup required here.
    if(!context_.archive.available()) {
        config_log().war("configuration archive restore rejected: native storage is unavailable");
        return {ArchiveRestoreStatus::native_unavailable, revision, hash, {}};
    }

    // Do not replace a restored archive before it has been activated.
    if(context_.archive.restart_required()) {
        config_log().war("configuration archive restore rejected: restart is already pending");
        return {ArchiveRestoreStatus::restart_pending, revision, hash, {}};
    }

    // The installer backs up the current archive before atomic publication.
    try {
        CfgSaveData prepared {payload, context_.archive.current()};
        if(!context_.archive.publish(prepared)) {
            config_log().err("configuration archive restore failed during publication");
            return {ArchiveRestoreStatus::write_failed, revision, hash, {}};
        }
    }
    catch(const std::exception& error) {
        config_log().err("configuration archive restore failed: %s", error.what());
        return {ArchiveRestoreStatus::write_failed, revision, hash, error.what()};
    }

    // Runtime remains unchanged; save is blocked until restart activates CFtar.
    context_.archive.require_restart();
    config_log().noti("configuration archive restore completed; restart is required");
    return {ArchiveRestoreStatus::restored, revision, std::move(hash), {}};
}

}  // namespace sx::cfg
