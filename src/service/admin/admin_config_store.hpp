#pragma once

#include "admin_config.hpp"

#include <service/cfgapi/cfg_resource_write.hpp>

#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace sx::admin {

enum class ChangeStatus {
    written,
    invalid_name,
    invalid_password,
    already_exists,
    not_found,
    last_enabled_administrator,
    persistence_error,
};

struct ChangeResult {
    ChangeStatus status {ChangeStatus::persistence_error};
    sx::cfg::ResourceWriteResult persistence;
    std::string detail;
    bool changed {false};

    [[nodiscard]] bool ok() const noexcept { return status == ChangeStatus::written; }
};

// Owns typed admin.cfg changes while delegating publication, concurrency,
// and recovery semantics to the shared configuration resource writer.
class ConfigStore {
public:
    struct Context {
        UpdateBoard& board;
        sx::cfg::CfgWriteGate& gate;
        std::recursive_mutex& config_mutex;
        sx::cfg::CfgArchiveStorage& archive;
    };

    explicit ConfigStore(Context context);

    // Reads and strictly parses admin.cfg from the current native archive.
    // A missing resource represents an empty, not-yet-configured admin store.
    [[nodiscard]] Admins read() const;

    // Authenticates against the current persisted admin.cfg snapshot.
    [[nodiscard]] AuthenticationStatus authenticate(
        std::string_view name, std::string_view password) const;

    // The following changes require the caller's expected revision and archive
    // hash. They publish admin.cfg atomically through the shared Core writer.
    ChangeResult create(std::string expected_revision,
                        std::string expected_archive_hash,
                        std::string name,
                        std::string_view password);
    ChangeResult change_password(std::string expected_revision,
                                 std::string expected_archive_hash,
                                 std::string_view name,
                                 std::string_view password);
    ChangeResult set_enabled(std::string expected_revision,
                             std::string expected_archive_hash,
                             std::string_view name,
                             bool enabled);
    ChangeResult remove(std::string expected_revision,
                        std::string expected_archive_hash,
                        std::string_view name);

private:
    using Change = std::function<ChangeStatus(Admins&)>;

    // Runs one typed change while the generic resource writer owns the shared
    // configuration gate. Rejected changes never publish a new archive.
    ChangeResult apply_change(std::string expected_revision,
                              std::string expected_archive_hash,
                              Change change);
    // Converts optional raw resource content to the typed model, applies the
    // requested change and returns serialized replacement content on success.
    static sx::cfg::ResourceTransformResult apply_to_content(
        const std::optional<std::string>& content,
        const Change& change,
        ChangeStatus& status);
    static ChangeStatus add_administrator(
        Admins& admins, std::string name, std::string verifier);
    static ChangeStatus replace_password(
        Admins& admins, std::string name, std::string verifier);
    static ChangeStatus update_enabled(
        Admins& admins, std::string_view name, bool enabled);
    static ChangeStatus erase_administrator(
        Admins& admins, std::string_view name);
    static Admins parse(std::optional<std::string> content);
    static std::size_t enabled_count(const Admins& admins) noexcept;

    Context context_;
};

} // namespace sx::admin
