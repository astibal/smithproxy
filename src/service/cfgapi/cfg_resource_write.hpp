#pragma once

#include <mutex>
#include <optional>
#include <string>

#include "cfg_archive_storage.hpp"
#include "cfg_update.hpp"
#include "cfg_write_gate.hpp"

namespace sx::cfg {

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

private:
    Context context_;
};

}  // namespace sx::cfg
