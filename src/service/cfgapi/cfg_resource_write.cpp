#include "cfg_resource_write.hpp"

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
    // The gate protects both the runtime revision and the cached archive. This
    // is essential after restore, when startup storage intentionally differs
    // from the still-running configuration.
    auto guard = context_.gate.enter(context_.config_mutex);
    if(!guard) {
        return {ResourceWriteStatus::lease_busy, context_.board.revision_state(), {}, {}};
    }

    const auto revision = context_.board.revision_state();
    if(revision.current_id != expected_revision)
        return {ResourceWriteStatus::stale_revision, revision, {}, {}};
    if(revision.unsaved)
        return {ResourceWriteStatus::unsaved_running, revision, {}, {}};
    if(context_.restart_pending || context_.external_change) {
        return {ResourceWriteStatus::write_failed, revision, {},
                "startup archive changed and requires restart"};
    }
    if(!context_.archive.available()) {
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
        return {ResourceWriteStatus::hash_mismatch, revision, current_hash, {}};
    }

    try {
        // prepare() edits a copy. The in-memory archive advances only after the
        // recovery copy and atomic active-file replacement both succeed.
        auto prepared = context_.archive.prepare(
            std::move(path), std::move(content), executable);
        if(!context_.archive.install(prepared)) {
            return {ResourceWriteStatus::write_failed, revision, current_hash, {}};
        }
        context_.archive.accept(prepared.replacement);
        context_.restart_pending = true;

        const auto replacement_hash = sx::crypto::sha256(prepared.replacement);
        return {ResourceWriteStatus::written, revision,
                replacement_hash ? "sha256:" + *replacement_hash : std::string {}, {}};
    }
    catch(const CfgTarError& error) {
        return {ResourceWriteStatus::invalid_resource, revision, current_hash, error.what()};
    }
    catch(const std::exception& error) {
        return {ResourceWriteStatus::write_failed, revision, current_hash, error.what()};
    }
}

}  // namespace sx::cfg
