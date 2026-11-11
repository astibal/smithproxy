#pragma once

#include <string>

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

private:
    CfgRuntimeTree(std::string generation, std::string root);
    void cleanup() noexcept;

    std::string generation_;
    std::string root_;
};

}  // namespace sx::cfg
