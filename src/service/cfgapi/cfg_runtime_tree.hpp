#pragma once

#include <string>

#include "cfg_tar.hpp"

namespace sx::cfg {

// Owns a private, read-only-by-convention filesystem view of one validated
// archive. It exists only for legacy consumers that require paths rather than
// in-memory resource bytes, notably custom-certificate directory discovery.
class CfgRuntimeTree {
public:
    static CfgRuntimeTree create(const CfgTar& archive);

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
