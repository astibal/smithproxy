#pragma once

#include <functional>
#include <mutex>
#include <optional>
#include <string>

#include "cfg_archive_storage.hpp"
#include "cfg_update.hpp"
#include "cfg_write_gate.hpp"

namespace sx::cfg {

enum class ResourceActivation {
    // Resource consumers only reload during process startup.
    deferred_until_restart,
    // The Core reads the published resource for each new operation.
    immediate,
};

enum class ResourceWriteStatus {
    written, invalid_resource, hash_mismatch, lease_busy, stale_revision,
    unsaved_running, native_unavailable, write_failed,
};

struct ResourceWriteResult {
    ResourceWriteStatus status {ResourceWriteStatus::write_failed};
    UpdateBoard::RevisionState revision;
    std::string archive_hash;
    std::string detail;
    [[nodiscard]] bool ok() const noexcept { return status == ResourceWriteStatus::written; }
};

struct ResourceTransformResult {
    bool apply = false;
    std::optional<std::string> content;
    std::string detail;
};

// Serializes one resource edit with every other configuration writer. Runtime
// objects remain unchanged; the resulting CFtar becomes active after restart.
class CfgResourceWriter {
public:
    struct Context {
        UpdateBoard& board;
        CfgWriteGate& gate;
        std::recursive_mutex& config_mutex;
        CfgArchiveStorage& archive;
    };

    explicit CfgResourceWriter(Context context);

    ResourceWriteResult write(std::string expected_revision,
                              std::string expected_archive_hash,
                              std::string path,
                              std::optional<std::string> content,
                              bool executable);

    // Atomically derive one managed resource from its current value while the
    // shared configuration write gate is held. A rejected transform never
    // publishes or mutates the cached archive.
    ResourceWriteResult transform(
        std::string expected_revision,
        std::string expected_archive_hash,
        std::string path,
        std::function<ResourceTransformResult(std::optional<std::string>)> transformer,
        bool executable,
        ResourceActivation activation = ResourceActivation::deferred_until_restart);

private:
    Context context_;
};

}  // namespace sx::cfg
