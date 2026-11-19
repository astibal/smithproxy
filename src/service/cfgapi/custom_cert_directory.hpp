#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>

namespace cfgapi_detail {

// The fallback must survive native configuration retirement. Resolve existing
// symlinks as well as lexical components before accepting the external path.
inline std::string custom_cert_directory(const std::string& value) {
    if (value.empty()) return {};
    const std::filesystem::path path(value);
    if (!path.is_absolute()) {
        throw std::invalid_argument("custom_cert_fallback_dir must be absolute");
    }
    // weakly_canonical leaves dangling symlinks unresolved. Reject those
    // rather than accepting a path whose later target could be managed state.
    std::filesystem::path prefix;
    for (const auto& component : path) {
        prefix /= component;
        std::error_code error;
        const auto status = std::filesystem::symlink_status(prefix, error);
        if (error && error != std::errc::no_such_file_or_directory) {
            throw std::filesystem::filesystem_error("cannot inspect custom certificate directory", prefix, error);
        }
        if (std::filesystem::is_symlink(status) && !std::filesystem::exists(prefix)) {
            throw std::invalid_argument("custom_cert_fallback_dir contains an unresolved symlink");
        }
    }
    const auto resolved = std::filesystem::weakly_canonical(path);
    const auto managed = std::filesystem::weakly_canonical("/etc/smithproxy");
    const auto relative = resolved.lexically_relative(managed);
    if (!relative.empty() && *relative.begin() != "..") {
        throw std::invalid_argument(
            "custom_cert_fallback_dir must be outside /etc/smithproxy");
    }
    // Keep a valid external symlink usable for atomic directory replacement.
    return path.string();
}

} // namespace cfgapi_detail
