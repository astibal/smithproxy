#include "cfg_runtime_tree.hpp"

#include <filesystem>
#include <utility>
#include <unistd.h>

namespace sx::cfg {

CfgRuntimeTree::CfgRuntimeTree(std::string generation, std::string root)
    : generation_(std::move(generation)), root_(std::move(root)) {}

CfgRuntimeTree CfgRuntimeTree::create(const CfgTar& archive) {
    std::string pattern = "/tmp/smithproxy-cftar-runtime-XXXXXX";
    if(!::mkdtemp(pattern.data())) {
        throw CfgTarError("cannot create private CFtar runtime generation");
    }

    const auto root = pattern + "/root";
    try {
        archive.materialize(root);
        return CfgRuntimeTree(std::move(pattern), root);
    }
    catch(...) {
        std::error_code ignored;
        std::filesystem::remove_all(pattern, ignored);
        throw;
    }
}

CfgRuntimeTree::CfgRuntimeTree(CfgRuntimeTree&& other) noexcept
    : generation_(std::exchange(other.generation_, {})),
      root_(std::exchange(other.root_, {})) {}

CfgRuntimeTree& CfgRuntimeTree::operator=(CfgRuntimeTree&& other) noexcept {
    if(this == &other) return *this;
    cleanup();
    generation_ = std::exchange(other.generation_, {});
    root_ = std::exchange(other.root_, {});
    return *this;
}

CfgRuntimeTree::~CfgRuntimeTree() {
    cleanup();
}

void CfgRuntimeTree::cleanup() noexcept {
    if(generation_.empty()) return;
    std::error_code ignored;
    std::filesystem::remove_all(generation_, ignored);
    generation_.clear();
    root_.clear();
}

}  // namespace sx::cfg
