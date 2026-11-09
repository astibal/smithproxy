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
    // Apply one resource edit to an isolated copy of the current archive.
    [[nodiscard]] virtual CfgSaveData prepare(
        std::string path,
        std::optional<std::string> content,
        bool executable) const = 0;
    // Persist recovery bytes and atomically publish the prepared archive.
    [[nodiscard]] virtual bool install(const CfgSaveData& prepared) const = 0;
    // Adopt successfully published bytes as the next archive write base.
    virtual void accept(std::string_view bytes) = 0;
};

}  // namespace sx::cfg
