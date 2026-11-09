#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "cfg_archive.hpp"

namespace sx::cfg {

// Defines the persistence boundary shared by archive restore and resource
// edits. Coordinators decide when a change is safe; the archive owner decides
// how candidates are prepared, published and adopted as the new write base.
class CfgArchiveStorage {
public:
    virtual ~CfgArchiveStorage() = default;

    // Report whether a writable native archive is currently available.
    [[nodiscard]] virtual bool available() const = 0;
    // Return the exact native archive bytes used as the publication base.
    [[nodiscard]] virtual std::string current() const = 0;
    // Replace the main configuration in an isolated archive copy.
    [[nodiscard]] virtual CfgSaveData prepare_main(
        std::string content) const = 0;
    // Apply one resource edit to an isolated copy of the current archive.
    [[nodiscard]] virtual CfgSaveData prepare_resource(
        std::string path,
        std::optional<std::string> content,
        bool executable) const = 0;
    // Persist recovery bytes, atomically publish the candidate and adopt it as
    // the next write base. A failed publication leaves cached state unchanged.
    [[nodiscard]] virtual bool publish(const CfgSaveData& prepared) const = 0;
};

}  // namespace sx::cfg
