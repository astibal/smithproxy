#include "cfg_archive.hpp"

#include <nlohmann/json.hpp>
#include <utils/crypto.hpp>

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

bool safe_logical_path(std::string_view path) {
    if (path.empty() || path.front() == '/' || path.back() == '/' ||
        path.find('\\') != std::string_view::npos ||
        path.find("//") != std::string_view::npos) {
        return false;
    }
    for (std::size_t start = 0; start < path.size();) {
        const auto end = path.find('/', start);
        const auto part = path.substr(start, end == std::string_view::npos
            ? path.size() - start : end - start);
        if (part == "." || part == "..") return false;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return true;
}

// Define the complete v1 archive namespace in one place. Unknown roots fail
// closed instead of becoming accidentally persistent product state.
bool allowed_path(std::string_view path) {
    if (path == CfgManifest::path || path == main_config_path || path == startup_config_path) {
        return true;
    }

    // These namespaces contain persistent configuration resources. Merely
    // storing a file under scripts/ never causes it to be executed.
    return CfgManifest::is_resource_path(path);
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

bool CfgManifest::is_resource_path(std::string_view path) {
    return safe_logical_path(path) &&
           (has_prefix(path, "pki/") || has_prefix(path, "messages/") ||
            has_prefix(path, "scripts/") || has_prefix(path, "ssh/"));
}

CfgResource::CfgResource(Kind kind, std::string logical_path, std::string value)
    : kind_(kind), logical_path_(std::move(logical_path)), value_(std::move(value)) {}

CfgResource::Kind CfgResource::kind() const noexcept {
    return kind_;
}

bool CfgResource::is_native() const noexcept {
    return kind_ == Kind::native;
}

const std::string& CfgResource::logical_path() const noexcept {
    return logical_path_;
}

const std::string& CfgResource::content() const {
    if (!is_native()) {
        fail("legacy CfgTar resource has no native content: " + logical_path_);
    }
    return value_;
}

const std::string& CfgResource::legacy_path() const {
    if (is_native()) {
        fail("native CfgTar resource has no legacy path: " + logical_path_);
    }
    return value_;
}

CfgArchive::CfgArchive(Kind kind, std::string path, std::optional<CfgTar> archive)
    : kind_(kind), path_(std::move(path)), archive_(std::move(archive)) {}

CfgArchive CfgArchive::open(Paths paths) {
    // Command-line intent is authoritative and keeps config-check workflows
    // independent of the system-wide CfgTar.
    if (paths.explicit_config) {
        return CfgArchive(Kind::legacy, std::move(*paths.explicit_config), std::nullopt);
    }

    // Existence, not successful parsing, controls fallback. A present but bad
    // archive is an operator-visible startup error rather than permission to
    // resurrect a potentially stale legacy configuration.
    if (path_exists(paths.archive)) {
        // Selection returns a ready-to-consume source. No caller can observe a
        // CfgTar Kind whose manifest or namespace has not passed validation.
        auto archive = CfgTar::read_file(paths.archive);
        CfgManifest::validate(archive);
        return CfgArchive(Kind::cftar, std::move(paths.archive), std::move(archive));
    }

    return CfgArchive(Kind::legacy, std::move(paths.legacy), std::nullopt);
}

// Reconstruct the same validated source model as open(), but use archive bytes
// obtained through the privileged file channel instead of opening the path.
CfgArchive CfgArchive::read_archive(std::string path, std::string_view bytes) {
    auto archive = CfgTar::read(bytes);
    CfgManifest::validate(archive);
    return CfgArchive(Kind::cftar, std::move(path), std::move(archive));
}

CfgArchiveInfo CfgArchive::inspect_archive(std::string_view bytes) {
    auto archive = CfgTar::read(bytes);
    CfgManifest::validate(archive);
    return CfgArchive(Kind::cftar, {}, std::move(archive)).info();
}

CfgArchive::Kind CfgArchive::kind() const noexcept {
    return kind_;
}

const std::string& CfgArchive::path() const noexcept {
    return path_;
}

bool CfgArchive::is_cftar() const noexcept {
    return kind_ == Kind::cftar;
}

CfgArchiveInfo CfgArchive::info() const {
    CfgArchiveInfo result;
    result.native = is_cftar();
    result.path = path_;
    if (!result.native) return result;

    result.format_version = CfgManifest::version;
    if(const auto hash = sx::crypto::sha256(archive().write())) {
        result.content_hash = "sha256:" + *hash;
    }
    result.entries.reserve(archive().entries().size());
    for (const auto& [path, entry] : archive().entries()) {
        result.payload_size += entry.data.size();
        result.entries.push_back({path, entry.data.size(), entry.executable});
    }
    return result;
}

const CfgTar& CfgArchive::archive() const {
    if (!archive_) {
        fail("legacy configuration has no CfgTar archive");
    }
    return *archive_;
}

std::string_view CfgArchive::main_config() const {
    return archive().at(main_config_path).data;
}

std::string_view CfgArchive::startup_config() const {
    return archive().at(startup_config_path).data;
}

CfgResource CfgArchive::resolve(std::string logical_path, std::string legacy_path) const {
    if (!CfgManifest::is_resource_path(logical_path)) {
        fail("invalid CfgTar resource path: " + logical_path);
    }

    // Presence is the only fallback decision. Content interpretation belongs
    // to its consumer, so malformed or empty native data can never resurrect a
    // stale legacy file behind the administrator's back.
    if (is_cftar() && archive().contains(logical_path)) {
        auto content = archive().at(logical_path).data;
        return {CfgResource::Kind::native, std::move(logical_path), std::move(content)};
    }
    if (legacy_path.empty()) {
        fail("legacy fallback path is empty for CfgTar resource: " + logical_path);
    }
    return {CfgResource::Kind::legacy, std::move(logical_path), std::move(legacy_path)};
}

std::vector<std::string> CfgArchive::resources(std::string_view logical_dir) const {
    if (logical_dir.empty() || logical_dir.back() != '/' ||
        !CfgManifest::is_resource_path(std::string(logical_dir) + "item")) {
        fail("invalid CfgTar resource directory: " + std::string(logical_dir));
    }

    std::vector<std::string> result;
    if (!is_cftar()) return result;
    for (const auto& [path, entry] : archive().entries()) {
        (void)entry;
        if (path.size() > logical_dir.size() &&
            path.compare(0, logical_dir.size(), logical_dir) == 0) {
            result.push_back(path);
        }
    }
    return result;
}

// Translate a new main configuration into the bytes expected by the selected
// persistent format. For CfgTar this also returns the exact accepted archive
// which must be made recoverable before the replacement is installed.
CfgSaveData CfgArchive::prepare_save(std::string main_config) const {
    if (!is_cftar()) {
        return {std::move(main_config), std::nullopt};
    }

    // Work on a copy so a failed validation or write cannot mutate the source
    // that still describes the configuration running in this process.
    auto updated = archive();
    updated.replace(main_config_path, std::move(main_config));
    CfgManifest::validate(updated);
    return {updated.write(), archive().write()};
}

CfgSaveData CfgArchive::prepare_resource(
    std::string path,
    std::optional<std::string> content,
    bool executable) const {
    if(!is_cftar()) fail("native resources require a CfgTar source");
    if(!CfgManifest::is_resource_path(path)) {
        fail("invalid CfgTar resource path: " + path);
    }

    // Work on a copy. The selected source must continue to describe durable
    // storage until the caller has backed up and published the replacement.
    auto updated = archive();
    if(content) {
        updated.upsert(std::move(path), std::move(*content), executable);
    }
    else if(!updated.remove(path)) {
        fail("cannot remove missing CfgTar resource: " + path);
    }

    CfgManifest::validate(updated);
    return {updated.write(), archive().write()};
}

// Advance the cached archive only after its prepared payload has reached disk.
// This keeps archive_payload() aligned with the last successful durable save.
void CfgArchive::accept_saved_main(std::string main_config) {
    if (!is_cftar()) {
        return;
    }
    archive_->replace(main_config_path, std::move(main_config));
    CfgManifest::validate(*archive_);
}

void CfgArchive::accept_saved_archive(std::string_view bytes) {
    if(!is_cftar()) fail("legacy configuration cannot adopt a CfgTar archive");
    auto updated = CfgTar::read(bytes);
    CfgManifest::validate(updated);
    archive_ = std::move(updated);
}

// Serialize the currently accepted native source byte-for-byte deterministically.
// archive() supplies the format check and rejects this operation for legacy.
std::string CfgArchive::archive_payload() const {
    return archive().write();
}

} // namespace sx::cfg
