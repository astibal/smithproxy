#include "cfg_save.hpp"

#include <utility>

namespace sx::cfg {

CfgSaver::CfgSaver(Context context)
    : context_(std::move(context)) {}

SaveResult CfgSaver::save(
    std::string const& expected_revision,
    std::string const& source) {
    // Ordinary writers cannot enter while a transaction lease is active.
    // The returned guard also owns config_mutex for the complete save.
    auto guard = context_.gate.enter(context_.config_mutex);
    if(!guard) {
        return {SaveStatus::lease_busy, context_.board.revision_state()};
    }

    auto const before = context_.board.revision_state();
    if(expected_revision != before.current_id) {
        return {SaveStatus::stale_revision, before};
    }
    if(!before.unsaved) {
        return {SaveStatus::unchanged, before};
    }
    if(context_.partial_config) {
        return {SaveStatus::partial_config, before};
    }
    if(!context_.save_file || !context_.save_file()) {
        return {SaveStatus::save_failed, before};
    }

    // Only a successful file write advances saved state. Because the guard is
    // still alive, another writer cannot create a revision between the write
    // and this bookkeeping update.
    context_.board.save(source);
    return {SaveStatus::saved, context_.board.revision_state()};
}

}  // namespace sx::cfg
