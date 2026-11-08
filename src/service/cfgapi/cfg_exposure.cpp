#include "cfg_exposure.hpp"

#include <filesystem>

namespace sx::cfg {

CfgExposure CfgExposureRegistry::expose(
    const CfgTar& archive, std::string logical_path) {
    // Materialize the complete validated generation so directory exposures
    // preserve their natural layout. The returned path may name either one
    // regular entry or an inferred directory inside that private generation.
    auto tree = CfgRuntimeTree::create(archive);
    auto filesystem_path = tree.root();
    if(!logical_path.empty()) filesystem_path += "/" + logical_path;

    std::error_code error;
    const auto status = std::filesystem::symlink_status(filesystem_path, error);
    if(error || !std::filesystem::exists(status)) {
        throw CfgTarError("CfgTar path cannot be exposed: " + logical_path);
    }

    // An exposure is a read-only snapshot even though the runtime tree uses
    // owner-writable files for legacy consumers inside Smithproxy.
    for(auto iterator = std::filesystem::recursive_directory_iterator(
            tree.root(), std::filesystem::directory_options::none, error);
        !error && iterator != std::filesystem::recursive_directory_iterator();
        iterator.increment(error)) {
        const auto permissions = iterator->is_directory()
            ? std::filesystem::perms::owner_all
            : std::filesystem::perms::owner_read;
        std::filesystem::permissions(
            iterator->path(), permissions, std::filesystem::perm_options::replace, error);
        if(error) break;
    }
    if(error) throw CfgTarError("cannot make CFtar exposure read-only");
    std::filesystem::permissions(
        tree.root(), std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace, error);
    if(error) throw CfgTarError("cannot protect CFtar exposure root");

    const auto id = next_id_++;
    CfgExposure info{id, std::move(logical_path), std::move(filesystem_path)};
    entries_.emplace(id, Owned{info, std::move(tree)});
    return info;
}

bool CfgExposureRegistry::close(std::uint64_t id) {
    // Erasing Owned destroys CfgRuntimeTree, which removes the private tree.
    return entries_.erase(id) != 0;
}

void CfgExposureRegistry::close_all() {
    entries_.clear();
}

std::vector<CfgExposure> CfgExposureRegistry::entries() const {
    // Copy only display metadata; the registry remains the sole tree owner.
    std::vector<CfgExposure> result;
    result.reserve(entries_.size());
    for(const auto& [id, exposure] : entries_) {
        (void)id;
        result.push_back(exposure.info);
    }
    return result;
}

}  // namespace sx::cfg
