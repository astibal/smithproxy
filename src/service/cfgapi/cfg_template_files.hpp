#pragma once

#include "cfg_tar.hpp"

namespace sx::cfg {

// Filesystem interchange uses a complete English set. Native archive names
// remain independent of the operator's export/import directory.
class CfgTemplateFiles {
public:
    static CfgTar read(const std::string& directory);
    static void write(const CfgTar& archive, const std::string& directory);
    static void validate(const CfgTar& templates);
};

} // namespace sx::cfg
