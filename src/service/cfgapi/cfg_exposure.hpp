#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "cfg_runtime_tree.hpp"

namespace sx::cfg {

struct CfgExposure {
    // Session-local handle used by "close exposure".
    std::uint64_t id {0};
    // Logical archive path requested by the administrator.
    std::string logical_path;
    // Temporary read-only path valid while the registry owns its tree.
    std::string filesystem_path;
};

// Owns read-only-file snapshots created by one interactive CFtar shell.
// Every exposure disappears when it is explicitly closed or the registry dies.
class CfgExposureRegistry {
public:
    // Materialize one read-only entry or directory snapshot and register it.
    CfgExposure expose(const CfgTar& archive, std::string logical_path);
    // Destroy one numbered exposure; return false when the id is unknown.
    bool close(std::uint64_t id);
    // Destroy every exposure owned by this interactive shell session.
    void close_all();
    // Return stable display metadata without transferring tree ownership.
    std::vector<CfgExposure> entries() const;

private:
    struct Owned {
        CfgExposure info;
        CfgRuntimeTree tree;
    };

    std::uint64_t next_id_ {1};
    std::map<std::uint64_t, Owned> entries_;
};

}  // namespace sx::cfg
