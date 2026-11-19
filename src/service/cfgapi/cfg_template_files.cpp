#include "cfg_template_files.hpp"
#include "cfg_pack.hpp"

#include <ext/nltemplate/nltemplate.hpp>
#include <resources/default_templates.hpp>

#include <filesystem>

namespace sx::cfg {
namespace {

constexpr auto prefix = "templates/replacement";
constexpr std::size_t prefix_size = sizeof("templates/replacement/") - 1;
constexpr std::size_t max_template_size = 1024U * 1024U;

// Reject extra directories too, including empty foreign-language directories.
// The subsequent descriptor-relative read independently rejects symlinks and
// non-regular files, so inspection never authorizes an unsafe filesystem read.
void check_layout(const std::string& directory) {
    namespace fs = std::filesystem;
    for(const auto& entry : fs::directory_iterator(directory)) {
        if(entry.path().filename() != "en" ||
           entry.symlink_status().type() != fs::file_type::directory) {
            throw CfgTarError("template import expects only an en directory");
        }
    }
    for(const auto& entry : fs::directory_iterator(fs::path(directory) / "en")) {
        if(entry.symlink_status().type() != fs::file_type::regular) {
            throw CfgTarError("template import requires regular files: " + entry.path().string());
        }
    }
}

} // namespace

void CfgTemplateFiles::validate(const CfgTar& templates) {
    const auto& defaults = resources::default_templates::all();
    if(templates.entries().size() != defaults.size()) {
        throw CfgTarError("template import requires the complete exported English set");
    }

    ext::nltemplate::LoaderMemory loader;
    for(const auto& [path, content] : defaults) {
        if(!templates.contains(path)) throw CfgTarError("missing template: " + path);
        const auto& entry = templates.at(path);
        if(entry.data.size() > max_template_size) {
            throw CfgTarError("template exceeds 1 MiB: " + path);
        }
        loader.add(path.substr(path.find_last_of('/') + 1), entry.data);
    }
    // Parse every variant, not only the active page. Includes resolve solely
    // against this immutable candidate, never against disk or live templates.
    for(const auto& [path, content] : defaults) {
        ext::nltemplate::Template candidate(loader);
        candidate.load(path.substr(path.find_last_of('/') + 1));
    }
}

CfgTar CfgTemplateFiles::read(const std::string& directory) {
    check_layout(directory);
    auto templates = CfgPack::read_directory(directory, prefix);
    validate(templates);
    return templates;
}

void CfgTemplateFiles::write(const CfgTar& archive, const std::string& directory) {
    CfgTar exported;
    for(const auto& [path, content] : resources::default_templates::all()) {
        // Export the actual selected contents, including operator edits.
        exported.add(path.substr(prefix_size), archive.at(path).data);
    }
    exported.materialize(directory);
}

} // namespace sx::cfg
