/*
 * Construction of a native configuration archive from filesystem inputs.
 */

#pragma once

#include <string>
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
    };

    struct Migration {
        Input input;
        std::string archive_path;
    };

    // Read every input exactly once, assemble the canonical v1 namespace and
    // validate the result before returning it to a writer.
    static CfgTar build(const Input& input);

    // Create the first native archive without replacing any path that appeared
    // concurrently. Returning false means another valid archive already owns
    // the destination; all other failures remain explicit exceptions.
    static bool migrate(const Migration& migration);
};

} // namespace sx::cfg
