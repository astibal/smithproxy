#include "cfg_source.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <utility>

namespace sx::cfg {
namespace {

constexpr std::string_view main_config_path = "smithproxy.cfg";
constexpr std::string_view startup_config_path = "smithproxy.startup.cfg";
constexpr std::size_t max_manifest_size = 4096;

// Keep all source and manifest failures in the CfgTar error domain. Callers
// can then report one coherent persistent-configuration startup failure.
[[noreturn]] void fail(const std::string& message) {
    throw CfgTarError(message);
}

// Match a non-empty archive path below a namespace directory. Requiring at
// least one character after the slash rejects directory placeholders.
bool has_prefix(std::string_view path, std::string_view prefix) {
    return path.size() > prefix.size() && path.compare(0, prefix.size(), prefix) == 0;
}

// Define the complete v1 archive namespace in one place. Unknown roots fail
// closed instead of becoming accidentally persistent product state.
bool allowed_path(std::string_view path) {
    if (path == CfgManifest::path || path == main_config_path || path == startup_config_path) {
        return true;
    }

    // These namespaces contain persistent configuration resources. Merely
    // storing a file under scripts/ never causes it to be executed.
    return has_prefix(path, "pki/") || has_prefix(path, "messages/") ||
           has_prefix(path, "scripts/") || has_prefix(path, "ssh/");
}

// Distinguish an absent archive from every other inspection error. Only
// ENOENT authorizes fallback; permission and filesystem errors remain fatal.
bool path_exists(const std::string& path) {
    struct stat state {};
    if (::lstat(path.c_str(), &state) == 0) {
        return true;
    }
    if (errno == ENOENT) {
        return false;
    }
    fail("cannot inspect configuration source " + path + ": " + std::strerror(errno));
}

} // namespace

std::string CfgManifest::canonical() {
    nlohmann::json manifest = {
        {"format", format},
        {"version", version},
    };
    return manifest.dump(2) + "\n";
}

void CfgManifest::validate(const CfgTar& archive) {
    // Refuse archives without an identity record before inspecting payload
    // files. This also keeps an ordinary TAR from masquerading as a CfgTar.
    if (!archive.contains(path)) {
        fail("CfgTar manifest is missing");
    }

    // The manifest is intentionally tiny. Bound it independently of the
    // archive limits so parsing can never become an expensive startup step.
    const auto& manifest_data = archive.at(path).data;
    if (manifest_data.size() > max_manifest_size) {
        fail("CfgTar manifest exceeds its size limit");
    }

    nlohmann::json manifest;
    try {
        manifest = nlohmann::json::parse(manifest_data);
    }
    catch (const nlohmann::json::exception& error) {
        fail("invalid CfgTar manifest: " + std::string(error.what()));
    }

    // Version 1 is a closed contract: exactly two typed fields are accepted.
    // Future extensions therefore require an explicit versioned code change
    // instead of being silently ignored by an older Smithproxy.
    if (!manifest.is_object() || manifest.size() != 2 ||
        !manifest.contains("format") || !manifest["format"].is_string() ||
        manifest["format"].get<std::string_view>() != format ||
        !manifest.contains("version") || !manifest["version"].is_number_unsigned() ||
        manifest["version"].get<unsigned int>() != version) {
        fail("unsupported CfgTar manifest");
    }

    // Both configuration views belong to one native archive. Requiring them
    // together prevents a partially migrated installation from starting.
    if (!archive.contains(main_config_path)) {
        fail("CfgTar main configuration is missing");
    }
    if (!archive.contains(startup_config_path)) {
        fail("CfgTar startup configuration is missing");
    }

    // Finally validate every stored resource, not merely files consumed by
    // this process today. This makes the archive boundary predictable for
    // backup, restore, privilege separation, and later schema migrations.
    for (const auto& [entry_path, entry] : archive.entries()) {
        (void)entry;
        if (!allowed_path(entry_path)) {
            fail("unsupported CfgTar path: " + entry_path);
        }
    }
}

CfgSource::CfgSource(Kind kind, std::string path, std::optional<CfgTar> archive)
    : kind_(kind), path_(std::move(path)), archive_(std::move(archive)) {}

CfgSource CfgSource::open(Paths paths) {
    // Command-line intent is authoritative and keeps config-check workflows
    // independent of the system-wide CfgTar.
    if (paths.explicit_config) {
        return CfgSource(Kind::legacy, std::move(*paths.explicit_config), std::nullopt);
    }

    // Existence, not successful parsing, controls fallback. A present but bad
    // archive is an operator-visible startup error rather than permission to
    // resurrect a potentially stale legacy configuration.
    if (path_exists(paths.archive)) {
        // Selection returns a ready-to-consume source. No caller can observe a
        // CfgTar Kind whose manifest or namespace has not passed validation.
        auto archive = CfgTar::read_file(paths.archive);
        CfgManifest::validate(archive);
        return CfgSource(Kind::cftar, std::move(paths.archive), std::move(archive));
    }

    return CfgSource(Kind::legacy, std::move(paths.legacy), std::nullopt);
}

CfgSource::Kind CfgSource::kind() const noexcept {
    return kind_;
}

const std::string& CfgSource::path() const noexcept {
    return path_;
}

bool CfgSource::is_cftar() const noexcept {
    return kind_ == Kind::cftar;
}

const CfgTar& CfgSource::archive() const {
    if (!archive_) {
        fail("legacy configuration has no CfgTar archive");
    }
    return *archive_;
}

std::string_view CfgSource::main_config() const {
    return archive().at(main_config_path).data;
}

std::string_view CfgSource::startup_config() const {
    return archive().at(startup_config_path).data;
}

} // namespace sx::cfg
