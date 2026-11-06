#pragma once

#include <functional>
#include <mutex>
#include <string>

#include "cfg_update.hpp"
#include "cfg_write_gate.hpp"

namespace sx::cfg {

enum class SaveStatus {
    saved,
    unchanged,
    lease_busy,
    stale_revision,
    partial_config,
    save_failed,
};

struct SaveResult {
    SaveStatus status {SaveStatus::save_failed};
    UpdateBoard::RevisionState revision;

    [[nodiscard]] bool ok() const noexcept {
        return status == SaveStatus::saved || status == SaveStatus::unchanged;
    }

    [[nodiscard]] bool changed() const noexcept {
        return status == SaveStatus::saved;
    }
};

using SaveFile = std::function<bool()>;

// Keeps the stable save infrastructure together. Callers provide only the
// revision they observed and the source recorded on UpdateBoard.
class CfgSaver {
public:
    struct Context {
        UpdateBoard& board;
        CfgWriteGate& gate;
        std::recursive_mutex& config_mutex;
        bool partial_config {false};
        SaveFile save_file;
    };

    explicit CfgSaver(Context context);

    // Save exactly the requested running revision. The write gate and config
    // mutex remain owned until the startup file and UpdateBoard agree.
    SaveResult save(
        std::string const& expected_revision,
        std::string const& source);

private:
    Context context_;
};

}  // namespace sx::cfg
