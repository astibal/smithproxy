#pragma once

#include "admin_config.hpp"

#include <service/cfgapi/cfg_resource_write.hpp>

#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace sx::admin {

enum class MutationStatus {
    written,
    invalid_name,
    invalid_password,
    already_exists,
    not_found,
    last_enabled_administrator,
    persistence_error,
};

struct MutationResult {
    MutationStatus status {MutationStatus::persistence_error};
    sx::cfg::ResourceWriteResult persistence;
    std::string detail;
    bool changed {false};

    [[nodiscard]] bool ok() const noexcept { return status == MutationStatus::written; }
};

// Owns typed admin.cfg mutations while delegating publication, concurrency,
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

    [[nodiscard]] Config read() const;
    [[nodiscard]] AuthenticationStatus authenticate(
        std::string_view name, std::string_view password) const;

    MutationResult create(std::string expected_revision,
                          std::string expected_archive_hash,
                          std::string name,
                          std::string_view password);
    MutationResult change_password(std::string expected_revision,
                                   std::string expected_archive_hash,
                                   std::string_view name,
                                   std::string_view password);
    MutationResult set_enabled(std::string expected_revision,
                               std::string expected_archive_hash,
                               std::string_view name,
                               bool enabled);
    MutationResult remove(std::string expected_revision,
                          std::string expected_archive_hash,
                          std::string_view name);

private:
    using Mutation = std::function<MutationStatus(Config&)>;

    MutationResult mutate(std::string expected_revision,
                          std::string expected_archive_hash,
                          Mutation mutation);
    static Config parse(std::optional<std::string> content);
    static std::size_t enabled_count(const Config& config) noexcept;

    Context context_;
};

} // namespace sx::admin
