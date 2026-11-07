/*
 * Selection and validation of Smithproxy's persistent configuration source.
 */

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

    // Report whether a logical path belongs to a persistent resource
    // namespace. Control files at the archive root are deliberately excluded.
    static bool is_resource_path(std::string_view path);
};

// Owns the result of one resource lookup. Native content is copied out of the
// current archive so callers may safely keep it across a configuration reload;
// a legacy result owns only the explicit filesystem path supplied by caller.
class CfgResource {
public:
    enum class Kind {
        native,
        legacy,
    };

    Kind kind() const noexcept;
    bool is_native() const noexcept;
    const std::string& logical_path() const noexcept;

    // Exactly one accessor is valid for each Kind. Misuse is a programming
    // error and fails explicitly rather than returning an ambiguous empty value.
    const std::string& content() const;
    const std::string& legacy_path() const;

private:
    friend class CfgSource;
    CfgResource(Kind kind, std::string logical_path, std::string value);

    Kind kind_;
    std::string logical_path_;
    std::string value_;
};

// Contains every byte needed for one persistent configuration replacement.
// Native storage carries the previously accepted archive as a recovery copy;
// legacy storage has no managed backup and therefore leaves previous empty.
struct CfgSaveData {
    std::string replacement;
    std::optional<std::string> previous;
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

    // Construct a native source from bytes supplied by a privileged reader.
    // This is the reload path after Smithproxy has dropped filesystem rights.
    static CfgSource read_archive(std::string path, std::string_view bytes);

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

    // Resolve one logical resource with a strict archive-first policy. An
    // existing archive entry always wins, including an empty entry. Only its
    // complete absence permits the caller-provided legacy path to be returned.
    CfgResource resolve(std::string logical_path, std::string legacy_path) const;

    // Enumerate native resources below one closed namespace. This exposes
    // stored scripts and macros to explicit administrative commands without
    // interpreting or executing their contents.
    std::vector<std::string> resources(std::string_view logical_dir) const;

    // Prepare a complete replacement and, for native storage, the exact
    // previously accepted archive. The caller persists previous first and
    // must not install replacement when that recovery write fails.
    CfgSaveData prepare_save(std::string main_config) const;

    // Advance the in-memory native source after its save payload has been
    // atomically installed. Legacy sources carry no cached file contents.
    void accept_saved_main(std::string main_config);

    // Return the exact current archive for a pre-upgrade backup. Legacy callers
    // already hold their parsed configuration and use its serialized form.
    std::string archive_payload() const;

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
