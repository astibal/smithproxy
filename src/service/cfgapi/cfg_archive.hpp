/*
 * Selection, validation, and mutation of Smithproxy's configuration archive.
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
    friend class CfgArchive;
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

// Safe administrative view of the persistent archive. Entry contents
// are intentionally absent so listing an archive can never disclose keys or
// other configuration material.
struct CfgArchiveInfo {
    struct Entry {
        std::string path;
        std::uint64_t size = 0;
        bool executable = false;
    };

    bool native = false;
    std::string path;
    unsigned int format_version = 0;
    std::uint64_t payload_size = 0;
    std::string content_hash;
    std::vector<Entry> entries;
};

// Owns Smithproxy's validated persistent configuration archive. During the
// migration window it can also represent one explicit legacy input, but that
// mode is an entrance ramp to CFtar rather than a parallel management model.
class CfgArchive {
public:
    // Describes whether startup selected native storage or its legacy entrance.
    enum class Kind {
        legacy,
        cftar,
    };

    // Supplies policy-free paths for production defaults and isolated tests.
    struct Paths {
        std::string archive;
        std::string legacy;
        std::optional<std::string> explicit_config = std::nullopt;
        std::optional<std::string> explicit_archive = std::nullopt;
    };

    // An explicit native archive or legacy migration input wins. Otherwise an
    // existing CfgTar is authoritative and fully validated; its absence opens
    // the one-time legacy entrance used to construct the first native archive.
    static CfgArchive open(Paths paths);

    // Derive native and optional startup siblings from an active legacy path.
    // A terminal .cfg is replaced; other names keep their complete basename.
    static std::string native_path_for(std::string_view legacy_path);
    static std::string startup_path_for(std::string_view legacy_path);

    // Construct a native archive from bytes supplied by a privileged reader.
    // This is the reload path after Smithproxy has dropped filesystem rights.
    static CfgArchive read_archive(std::string path, std::string_view bytes);

    // Parse and fully validate an uploaded archive without selecting or
    // mutating the running configuration archive.
    static CfgArchiveInfo inspect_archive(std::string_view bytes);

    // Describe the selected format and persistent path. These accessors do not
    // perform I/O; selection and validation are complete after open().
    Kind kind() const noexcept;
    const std::string& path() const noexcept;
    bool is_cftar() const noexcept;

    // Describe the archive without exposing entry contents. Legacy inputs
    // report only their path; native archives include validated metadata.
    CfgArchiveInfo info() const;

    // Available only in native mode. Legacy loading remains isolated behind
    // the privileged file reader until migration creates CFtar.
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

    // Prepare one resource edit in a copied archive. nullopt removes an
    // existing resource; content adds or replaces it. Control files cannot be
    // changed through this interface.
    CfgSaveData prepare_resource(std::string path,
                                 std::optional<std::string> content,
                                 bool executable = false) const;

    // Advance the in-memory native archive after its save payload has been
    // atomically installed. Legacy inputs carry no cached file contents.
    void accept_saved_main(std::string main_config);

    // Adopt a fully written archive after durable publication succeeds.
    void accept_saved_archive(std::string_view bytes);

    // Return the exact current archive for a pre-upgrade backup. Legacy callers
    // already hold their parsed configuration and use its serialized form.
    std::string archive_payload() const;

private:
    // Construction stays private to prevent unvalidated CfgTar archives from
    // being assembled by callers.
    CfgArchive(Kind kind, std::string path, std::optional<CfgTar> archive);

    // The optional archive is populated exactly when kind_ is cftar.
    Kind kind_;
    std::string path_;
    std::optional<CfgTar> archive_;
};

} // namespace sx::cfg
