#pragma once

#include <string>
#include <sys/types.h>

#include "cfg_io.hpp"
#include "cfg_tar.hpp"

namespace sx::cfg {

// Owns a private, read-only-by-convention filesystem view of one validated
// archive. It exists only for legacy consumers that require paths rather than
// in-memory resource bytes, notably custom-certificate directory discovery.
class CfgRuntimeTree {
public:
    // Materialize an archive through the production filesystem provider.
    static CfgRuntimeTree create(const CfgTar& archive);
    // Materialize through an alternate provider for deterministic failures or
    // platform-specific temporary-directory handling.
    static CfgRuntimeTree create(const CfgTar& archive, CfgIoPtr io);

    CfgRuntimeTree(const CfgRuntimeTree&) = delete;
    CfgRuntimeTree& operator=(const CfgRuntimeTree&) = delete;
    CfgRuntimeTree(CfgRuntimeTree&& other) noexcept;
    CfgRuntimeTree& operator=(CfgRuntimeTree&& other) noexcept;
    ~CfgRuntimeTree();

    const std::string& root() const noexcept { return root_; }

    // Called while still privileged, before the core changes identity.
    // Only this disposable view changes ownership; the source archive does not.
    void transfer_owner(uid_t uid, gid_t gid);

private:
    CfgRuntimeTree(std::string generation, std::string root);
    void cleanup() noexcept;

    std::string generation_;
    std::string root_;
};

}  // namespace sx::cfg
