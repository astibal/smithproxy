#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sx::admin {

inline constexpr int config_schema_version = 1;

enum class AuthenticationStatus {
    not_configured,
    denied,
    authenticated,
};

// Administrator identifiers are shared by enrollment, persistent storage,
// and every management transport.
// Returns true only for names that can safely identify one managed account.
bool valid_name(std::string_view value);

struct Administrator {
    std::string name;
    bool enabled = true;
    std::string password_verifier;

    bool operator==(const Administrator& other) const noexcept;
};

// Core-owned local authentication transport policy. An omitted path selects
// the tenant-aware runtime default; it is never derived from gui.cfg.
struct AuthenticationPolicy {
    bool socket_enabled {true};
    std::optional<std::filesystem::path> socket_path;
};

// Owns the typed representation of admin.cfg. Parsing is deliberately strict:
// invalid credentials must never become a partially active configuration.
class Admins {
public:
    // Parses and validates the complete admin.cfg resource. Invalid schemas,
    // duplicate names and unsupported password verifiers are rejected.
    static Admins parse(std::string_view content);

    // Serializes the complete typed model into canonical admin.cfg content.
    [[nodiscard]] std::string serialize() const;
    [[nodiscard]] const std::vector<Administrator>& administrators() const noexcept;
    [[nodiscard]] const AuthenticationPolicy& authentication() const noexcept;
    [[nodiscard]] const Administrator* find(std::string_view name) const noexcept;

    // Authenticates one enabled administrator. Returns not_configured when no
    // managed administrators exist so the caller may apply a legacy fallback.
    [[nodiscard]] AuthenticationStatus authenticate(
        std::string_view name, std::string_view password) const;

    // Inserts or replaces one validated administrator by name.
    void upsert(Administrator administrator);

    // Removes one administrator and reports whether the name existed.
    bool remove(std::string_view name);

private:
    AuthenticationPolicy authentication_;
    std::vector<Administrator> administrators_;
};

} // namespace sx::admin
