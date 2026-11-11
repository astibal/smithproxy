#include "cfg_save.hpp"
#include "cfg_log.hpp"

#include <utility>

namespace sx::cfg {

CfgSaver::CfgSaver(Context context)
    : context_(std::move(context)) {}

SaveResult CfgSaver::save(
    std::string const& expected_revision,
    std::string const& source) {
    // Ordinary writers cannot enter while a transaction lease is active.
    // The returned guard also owns config_mutex for the complete save.
    config_log().inf("configuration save requested: source=%s", source.c_str());
    auto guard = context_.gate.enter(context_.config_mutex);
    if(!guard) {
        config_log().war("configuration save rejected: write lease is busy");
        return {SaveStatus::lease_busy, context_.board.revision_state()};
    }

    auto const before = context_.board.revision_state();
    if(expected_revision != before.current_id) {
        config_log().war("configuration save rejected: expected revision is stale");
        return {SaveStatus::stale_revision, before};
    }
    if(!before.unsaved) {
        config_log().dia("configuration save skipped: persistent state is current");
        return {SaveStatus::unchanged, before};
    }
    if(context_.partial_config) {
        config_log().war("configuration save rejected: running configuration is partial");
        return {SaveStatus::partial_config, before};
    }
    if(!context_.save_file || !context_.save_file()) {
        config_log().err("configuration save failed while publishing persistent state");
        return {SaveStatus::save_failed, before};
    }

    // Only a successful file write advances saved state. Because the guard is
    // still alive, another writer cannot create a revision between the write
    // and this bookkeeping update.
    context_.board.save(source);
    config_log().noti("configuration save completed: source=%s", source.c_str());
    return {SaveStatus::saved, context_.board.revision_state()};
}

}  // namespace sx::cfg
