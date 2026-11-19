#include "cfg_runtime_tree.hpp"

#include <filesystem>
#include <utility>
#include <vector>
#include <unistd.h>

namespace sx::cfg {

CfgRuntimeTree::CfgRuntimeTree(std::string generation, std::string root)
    : generation_(std::move(generation)), root_(std::move(root)) {}

CfgRuntimeTree CfgRuntimeTree::create(const CfgTar& archive) {
    return create(archive, std::make_shared<CfgIo>());
}

CfgRuntimeTree CfgRuntimeTree::create(const CfgTar& archive, CfgIoPtr io) {
    if(!io) throw CfgTarError("CFtar runtime I/O provider is not available");
    std::string pattern = "/tmp/smithproxy-cftar-runtime-XXXXXX";
    if(io->create_temp_directory(pattern) != 0) {
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

void CfgRuntimeTree::transfer_owner(uid_t uid, gid_t gid) {
    if(generation_.empty()) return;

    // The enclosing 0700 generation stays root-owned until every descendant
    // is ready. The receiving user cannot enter and replace paths midway.
    std::vector<std::filesystem::path> paths;
    for(const auto& entry : std::filesystem::recursive_directory_iterator(generation_)) {
        const auto type = entry.symlink_status().type();
        if(type != std::filesystem::file_type::regular &&
           type != std::filesystem::file_type::directory) {
            throw CfgTarError("unexpected file type in private CFtar runtime tree");
        }
        paths.push_back(entry.path());
    }
    paths.emplace_back(generation_);

    for(const auto& path : paths) {
        if(::lchown(path.c_str(), uid, gid) != 0) {
            throw CfgTarError("cannot transfer private CFtar runtime tree ownership");
        }
    }
}

void CfgRuntimeTree::cleanup() noexcept {
    if(generation_.empty()) return;
    std::error_code ignored;
    std::filesystem::remove_all(generation_, ignored);
    generation_.clear();
    root_.clear();
}

}  // namespace sx::cfg
