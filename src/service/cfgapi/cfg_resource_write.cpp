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
    // A direct write is the unconditional form of the guarded transform API.
    return transform(
        std::move(expected_revision), std::move(expected_archive_hash), std::move(path),
        [content = std::move(content)](const std::optional<std::string>&) mutable {
            if(!content) {
                return ResourceTransformResult{
                    ResourceTransformAction::remove, {}, {}};
            }
            return ResourceTransformResult{
                ResourceTransformAction::replace, std::move(content), {}};
        },
        executable);
}

ResourceWriteResult CfgResourceWriter::transform(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string path,
    std::function<ResourceTransformResult(
        const std::optional<std::string>&)> transformer,
    bool executable,
    ResourceActivation activation) {
    // Keep the gate across validation, transformation and publication so two
    // writers cannot derive replacements from the same archive generation.
    const auto resource = path;
    config_log().inf("configuration resource transform requested: resource=%s",
                     resource.c_str());
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
    const bool deferred_activation =
        activation == ResourceActivation::deferred_until_restart;
    if(deferred_activation && context_.archive.restart_required()) {
        config_log().war("configuration resource update rejected: restart is pending");
        return {ResourceWriteStatus::write_failed, revision, {},
                "startup archive changed and requires restart"};
    }
    if(!context_.archive.available()) {
        config_log().war("configuration resource update rejected: native storage is unavailable");
        return {ResourceWriteStatus::native_unavailable, revision, {}, {}};
    }

    // The caller supplies both runtime revision and archive content identity.
    // Both must still describe the generation transformed below.
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
        const auto archive = CfgArchive::read_archive(
            smithproxy_schema(), "active.cftar", current);
        std::optional<std::string> current_content;
        if(archive.archive().contains(path)) current_content = archive.archive().at(path).data;

        // The semantic owner validates and transforms only its resource. It
        // cannot publish anything directly or bypass archive invariants.
        auto transformed = transformer(current_content);
        const bool replace_resource =
            transformed.action == ResourceTransformAction::replace;
        const bool remove_resource =
            transformed.action == ResourceTransformAction::remove;
        const bool reject_resource =
            transformed.action == ResourceTransformAction::reject;
        const bool leave_resource_unchanged =
            transformed.action == ResourceTransformAction::unchanged;
        const bool known_action = replace_resource || remove_resource ||
            reject_resource || leave_resource_unchanged;
        const bool missing_replacement = replace_resource && !transformed.content;
        const bool unexpected_content = !replace_resource && transformed.content.has_value();
        if(!known_action || missing_replacement || unexpected_content) {
            config_log().war(
                "configuration resource transform returned an inconsistent result: resource=%s",
                resource.c_str());
            return {ResourceWriteStatus::invalid_resource, revision, current_hash,
                    "inconsistent resource transform result"};
        }

        if(transformed.action == ResourceTransformAction::reject) {
            config_log().war("configuration resource transform rejected: resource=%s detail=%s",
                             resource.c_str(), transformed.detail.c_str());
            return {ResourceWriteStatus::invalid_resource, revision, current_hash,
                    std::move(transformed.detail)};
        }
        if(transformed.action == ResourceTransformAction::unchanged) {
            config_log().inf("configuration resource transform is unchanged: resource=%s",
                             resource.c_str());
            return {ResourceWriteStatus::written, revision, current_hash, {}};
        }

        const bool resource_absent = !current_content;
        const bool content_unchanged = replace_resource &&
            transformed.content == current_content;
        const bool removal_unchanged = remove_resource && resource_absent;
        if(content_unchanged || removal_unchanged) {
            config_log().inf("configuration resource transform is unchanged: resource=%s",
                             resource.c_str());
            return {ResourceWriteStatus::written, revision, current_hash, {}};
        }

        const auto operation_name = remove_resource ? "remove" : "upsert";
        std::optional<std::string> replacement;
        if(replace_resource) replacement = std::move(transformed.content);

        // prepare() edits a copy. The in-memory archive advances only after the
        // recovery copy and atomic active-file replacement both succeed.
        auto prepared = context_.archive.prepare_resource(
            std::move(path), std::move(replacement), executable);
        if(!context_.archive.publish(prepared)) {
            config_log().err("configuration resource update failed during publication");
            return {ResourceWriteStatus::write_failed, revision, current_hash, {}};
        }
        if(deferred_activation) context_.archive.require_restart();

        const auto replacement_hash = sx::crypto::sha256(prepared.replacement);
        config_log().noti("configuration resource update completed: resource=%s operation=%s",
                          resource.c_str(), operation_name);
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
