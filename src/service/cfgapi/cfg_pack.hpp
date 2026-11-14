/*
 * Construction of a native configuration archive from filesystem inputs.
 */

#pragma once

#include <string>
#include <map>
#include <vector>

#include <service/cfgapi/cfg_tar.hpp>

namespace sx::cfg {

// Builds a complete in-memory CfgTar from explicitly named legacy files.
// Filesystem access is kept here so command-line migration and future runtime
// migration share the same no-symlink and regular-file policy.
class CfgPack {
public:
    struct File {
        std::string archive_path;
        std::string source_path;
        bool executable = false;
        bool optional = false;
    };

    struct Directory {
        // Native prefix receiving every regular descendant of source_path.
        std::string archive_prefix;
        // Legacy root opened without following a final symlink.
        std::string source_path;
        // Only a genuinely absent root may be skipped; unsafe content fails.
        bool optional = false;
    };

    struct Input {
        std::string main_config;
        std::string startup_config;
        std::vector<File> files;
        std::vector<Directory> directories;
        // Legacy installations may never have created the optional network
        // startup file. Only ENOENT becomes an empty native startup entry;
        // malformed, unreadable and unsafe inputs still fail migration.
        bool allow_missing_startup = false;
        // Explicit schema migration inputs, used only for absent resource names.
        std::map<std::string, std::string> resource_defaults = {};
    };

    struct Migration {
        Input input;
        std::string archive_path;
    };

    struct LegacyRetireResult {
        bool backup_created = false;
        std::size_t files_removed = 0;
    };

    // Read every input exactly once, assemble the canonical v1 namespace and
    // validate the result before returning it to a writer.
    static CfgTar build(const Input& input);

    // Create the first native archive without replacing any path that appeared
    // concurrently. Returning false means another valid archive already owns
    // the destination; all other failures remain explicit exceptions.
    static bool migrate(const Migration& migration);

    // Startup-only caller: retire the selected legacy input after native activation.
    // An omitted legacy path selects the sibling .cfg of an explicit CFtar.
    // Never overwrite a backup; return its path, or empty when the source is absent.
    static std::string retire_legacy_config(
        const std::string& archive_path, const std::string& legacy_path = {});

    // Preserve the pre-CFtar /etc tree in one plain TAR and remove the
    // individual files only after both native and legacy archives validate.
    // Repeated calls finish an interrupted cleanup against the same memento.
    static LegacyRetireResult retire_legacy_tree(
        const std::string& root,
        const std::string& active_archive,
        const std::string& backup_name);
};

} // namespace sx::cfg
