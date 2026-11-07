#pragma once

#include <functional>
#include <mutex>
#include <string>

#include "cfg_update.hpp"
#include "cfg_write_gate.hpp"

namespace sx::cfg {

enum class ArchiveRestoreStatus {
    restored, invalid_archive, hash_mismatch, lease_busy, stale_revision,
    unsaved_running, native_unavailable, restart_pending, write_failed,
};

struct ArchiveRestoreResult {
    ArchiveRestoreStatus status {ArchiveRestoreStatus::write_failed};
    UpdateBoard::RevisionState revision;
    std::string content_hash;
    std::string detail;
    [[nodiscard]] bool ok() const noexcept { return status == ArchiveRestoreStatus::restored; }
};

using ArchiveReader = std::function<std::string()>;
using ArchiveWriter = std::function<bool(const std::string&, const std::string&)>;

// Coordinates replacement of the next-start archive. It deliberately leaves
// running configuration untouched: resources such as keys and certificates
// do not all support a safe live reload yet.
class CfgArchiveRestorer {
public:
    struct Context {
        // Restore shares synchronization with every other config writer.
        UpdateBoard& board;
        CfgWriteGate& gate;
        std::recursive_mutex& config_mutex;

        // Two archives must not replace each other before either is activated.
        bool native_source = false;
        bool& restart_pending;

        // Storage policy remains in CfgFactory and privileged-file code.
        ArchiveReader current_archive;
        ArchiveWriter install;
    };

    explicit CfgArchiveRestorer(Context context);

    // Install payload as the next startup archive without changing runtime.
    // Hash and revision bind it to the state previously inspected by the user.
    ArchiveRestoreResult restore(const std::string& expected_revision,
                                 const std::string& expected_hash,
                                 const std::string& payload);

private:
    Context context_;
};

}  // namespace sx::cfg
