#include "cfg_template_maintenance.hpp"
#include "cfg_template_files.hpp"

#include <resources/default_templates.hpp>

namespace sx::cfg {

CfgTemplateMaintainer::CfgTemplateMaintainer(Context context): context_(context) {}

std::size_t CfgTemplateMaintainer::apply(TemplateMaintenance mode) {
    CfgTar templates;
    for(const auto& [path, content] : resources::default_templates::all()) {
        templates.add(path, content);
    }
    return publish_templates(templates, mode == TemplateMaintenance::fix_missing);
}

std::size_t CfgTemplateMaintainer::import_directory(const std::string& directory) {
    // Validate a complete snapshot before taking the configuration write gate.
    return publish_templates(CfgTemplateFiles::read(directory), false);
}

void CfgTemplateMaintainer::export_directory(const std::string& directory) {
    std::string snapshot;
    {
        std::scoped_lock lock(context_.config_mutex);
        if(!context_.archive.available()) {
            throw CfgTarError("template export requires a native CFtar archive");
        }
        snapshot = context_.archive.current();
    }
    CfgTemplateFiles::write(CfgTar::read(snapshot), directory);
}

std::size_t CfgTemplateMaintainer::publish_templates(const CfgTar& templates, bool only_missing) {
    // Read, prepare and publish under the same gate. Another resource writer
    // cannot slip a change between our snapshot and its replacement.
    auto guard = context_.gate.enter(context_.config_mutex);
    if(!guard) {
        throw CfgTarError("configuration is locked by an active commit lease");
    }
    if(context_.board.revision_state().unsaved) {
        throw CfgTarError("save or discard running configuration changes first");
    }
    if(!context_.archive.available()) {
        throw CfgTarError("template maintenance requires a native CFtar archive");
    }
    if(context_.archive.restart_required()) {
        throw CfgTarError("startup archive has pending changes; restart first");
    }

    const auto previous = context_.archive.current();
    auto updated = CfgTar::read(previous);
    std::size_t changed = 0;
    for(const auto& [path, entry] : templates.entries()) {
        const auto& content = entry.data;
        if(updated.contains(path)) {
            if(only_missing) continue;
            const auto& existing = updated.at(path);
            if(existing.data == content && !existing.executable) continue;
        }
        updated.upsert(path, content);
        ++changed;
    }

    // Avoid replacing the previous-generation backup on a no-op invocation.
    if(changed == 0) return 0;
    CfgManifest::validate(updated);
    if(!context_.archive.publish({updated.write(), previous})) {
        throw CfgTarError("cannot publish template changes; inspect archive storage status");
    }
    context_.archive.require_restart();
    return changed;
}

} // namespace sx::cfg
