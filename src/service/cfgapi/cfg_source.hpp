/*
 * Selection and validation of Smithproxy's persistent configuration source.
 */

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <service/cfgapi/cfg_tar.hpp>

namespace sx::cfg {

// Defines and validates the small control record at the root of every CfgTar.
// The manifest identifies the archive format and guards its complete namespace,
// so a newer or foreign archive is rejected before any configuration is used.
class CfgManifest {
public:
    static constexpr std::string_view path = "manifest.json";
    static constexpr std::string_view format = "smithproxy-cftar";
    static constexpr unsigned int version = 1;

    // Return the canonical manifest stored in newly created archives.
    static std::string canonical();

    // Validate the manifest and the complete archive namespace. The main and
    // startup configurations are mandatory; unknown top-level paths fail.
    static void validate(const CfgTar& archive);
};

// Resolves the persistent configuration source used for one process start.
// It preserves an explicit legacy-file request, otherwise prefers CfgTar and
// permits legacy fallback only when the archive is genuinely absent. A chosen
// CfgTar is already parsed and validated, making later accessors safe to use.
class CfgSource {
public:
    // Describes which storage format won source selection.
    enum class Kind {
        legacy,
        cftar,
    };

    // Supplies policy-free paths so callers can use production defaults or
    // isolated test locations without changing source-selection semantics.
    struct Paths {
        std::string archive;
        std::string legacy;
        std::optional<std::string> explicit_config;
    };

    // An explicit configuration file wins. Otherwise an existing CfgTar is
    // preferred and fully validated. Only an absent CfgTar permits fallback.
    static CfgSource open(Paths paths);

    // Describe the selected format and the exact source path. These accessors
    // do not perform I/O; source selection is complete after open().
    Kind kind() const noexcept;
    const std::string& path() const noexcept;
    bool is_cftar() const noexcept;

    // Available only for a CfgTar source. Legacy loading remains in the
    // existing privileged file path until the runtime integration patch.
    const CfgTar& archive() const;
    std::string_view main_config() const;
    std::string_view startup_config() const;

private:
    // Construction stays private to prevent unvalidated CfgTar sources from
    // being assembled by callers.
    CfgSource(Kind kind, std::string path, std::optional<CfgTar> archive);

    // The optional archive is populated exactly when kind_ is cftar.
    Kind kind_;
    std::string path_;
    std::optional<CfgTar> archive_;
};

} // namespace sx::cfg
