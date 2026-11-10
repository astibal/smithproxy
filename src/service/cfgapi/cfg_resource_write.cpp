#include "cfg_resource_write.hpp"
#include "cfg_log.hpp"

#include <utils/crypto.hpp>

#include <utility>

namespace sx::cfg {

CfgResourceWriter::CfgResourceWriter(Context context): context_(std::move(context)) {}

ResourceWriteResult CfgResourceWriter::write(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string path,
    std::optional<std::string> content,
    bool executable) {
    const auto operation = content ? "upsert" : "remove";
    const auto resource = path;
    config_log().inf("configuration resource update requested: resource=%s operation=%s",
                     resource.c_str(), operation);
    // The gate protects both the runtime revision and the cached archive. This
    // is essential after restore, when startup storage intentionally differs
    // from the still-running configuration.
    auto guard = context_.gate.enter(context_.config_mutex);
    if(!guard) {
        config_log().war("configuration resource update rejected: write lease is busy");
        return {ResourceWriteStatus::lease_busy, context_.board.revision_state(), {}, {}};
    }

    const auto revision = context_.board.revision_state();
    if(revision.current_id != expected_revision) {
        config_log().war("configuration resource update rejected: expected revision is stale");
        return {ResourceWriteStatus::stale_revision, revision, {}, {}};
    }
    if(revision.unsaved) {
        config_log().war("configuration resource update rejected: running configuration is unsaved");
        return {ResourceWriteStatus::unsaved_running, revision, {}, {}};
    }
    if(context_.archive.restart_required()) {
        config_log().war("configuration resource update rejected: restart is pending");
        return {ResourceWriteStatus::write_failed, revision, {},
                "startup archive changed and requires restart"};
    }
    if(!context_.archive.available()) {
        config_log().war("configuration resource update rejected: native storage is unavailable");
        return {ResourceWriteStatus::native_unavailable, revision, {}, {}};
    }

    const auto current = context_.archive.current();
    const auto digest = sx::crypto::sha256(current);
    if(!digest) {
        return {ResourceWriteStatus::write_failed, revision, {},
                "cannot hash current configuration archive"};
    }
    const auto current_hash = "sha256:" + *digest;
    if(current_hash != expected_archive_hash) {
        config_log().war("configuration resource update rejected: archive generation is stale");
        return {ResourceWriteStatus::hash_mismatch, revision, current_hash, {}};
    }

    try {
        // prepare() edits a copy. The in-memory archive advances only after the
        // recovery copy and atomic active-file replacement both succeed.
        auto prepared = context_.archive.prepare_resource(
            std::move(path), std::move(content), executable);
        if(!context_.archive.publish(prepared)) {
            config_log().err("configuration resource update failed during publication");
            return {ResourceWriteStatus::write_failed, revision, current_hash, {}};
        }
        context_.archive.require_restart();

        const auto replacement_hash = sx::crypto::sha256(prepared.replacement);
        config_log().noti("configuration resource update completed: resource=%s operation=%s",
                          resource.c_str(), operation);
        return {ResourceWriteStatus::written, revision,
                replacement_hash ? "sha256:" + *replacement_hash : std::string {}, {}};
    }
    catch(const CfgTarError& error) {
        config_log().war("configuration resource update rejected: %s", error.what());
        return {ResourceWriteStatus::invalid_resource, revision, current_hash, error.what()};
    }
    catch(const std::exception& error) {
        config_log().err("configuration resource update failed: %s", error.what());
        return {ResourceWriteStatus::write_failed, revision, current_hash, error.what()};
    }
}

}  // namespace sx::cfg
