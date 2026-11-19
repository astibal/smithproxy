#pragma once

#include <cstddef>
#include <mutex>

#include "cfg_archive_storage.hpp"
#include "cfg_update.hpp"
#include "cfg_write_gate.hpp"

namespace sx::cfg {

enum class TemplateMaintenance { rollback, fix_missing };

// Administrative template changes share the configuration write gate and
// publish one complete archive. Runtime activation remains explicit.
class CfgTemplateMaintainer {
public:
    struct Context {
        UpdateBoard& board;
        CfgWriteGate& gate;
        std::recursive_mutex& config_mutex;
        CfgArchiveStorage& archive;
    };

    explicit CfgTemplateMaintainer(Context context);

    // Return the number of changed templates. Zero means no write or restart.
    // Failures throw CfgTarError; the existing archive remains the write base.
    std::size_t apply(TemplateMaintenance mode);
    std::size_t import_directory(const std::string& directory);
    void export_directory(const std::string& directory);

private:
    std::size_t publish_templates(const CfgTar& templates, bool only_missing);

    Context context_;
};

} // namespace sx::cfg
