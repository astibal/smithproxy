#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

namespace sx::auth {

// Core-owned runtime credential pair shared with a trusted Smithproxy
// component. Persistent configuration contains paths and rotation policy,
// never credential values.
struct RuntimeCredentialSpec {
    bool enabled {false};
    std::filesystem::path current_path;
    std::filesystem::path previous_path;
    // A launcher may seed current shortly before Core starts. Older material
    // is rotated immediately instead of being mistaken for this boot's seed.
    std::chrono::seconds bootstrap_freshness {std::chrono::minutes(5)};
    std::chrono::seconds rotation_interval {std::chrono::hours(24)};
    std::chrono::seconds overlap {std::chrono::hours(1)};
};

struct RuntimeCredentialSnapshot {
    std::optional<std::string> current;
    std::optional<std::string> previous;
};

struct GuiRuntimeCredentialPolicy {
    RuntimeCredentialSpec management_api;
    RuntimeCredentialSpec gateway;
    bool administrator_auth_socket_enabled {true};
    std::filesystem::path administrator_auth_socket {
        "/run/smithproxy/admin-auth.sock"};
};

// Reads only Core-owned runtime credential policy from gui.cfg. The rest of
// the GUI schema remains private to smithproxy-gui.
GuiRuntimeCredentialPolicy parse_gui_runtime_credentials(std::string_view source);
GuiRuntimeCredentialPolicy default_gui_runtime_credentials();

class RuntimeCredentialPair {
public:
    using Publish = std::function<void(const RuntimeCredentialSnapshot&)>;
    using Log = std::function<void(bool warning, std::string_view)>;

    RuntimeCredentialPair(RuntimeCredentialSpec spec, Publish publish, Log log = {});

    // Reconciles the pair once. Exposed so startup and tests do not depend on
    // worker timing. Failure never blocks the proxy data plane.
    bool reconcile(std::chrono::system_clock::time_point now =
                       std::chrono::system_clock::now());

    void start(std::chrono::seconds poll_interval = std::chrono::seconds(5));
    void stop();
    ~RuntimeCredentialPair();

    RuntimeCredentialPair(const RuntimeCredentialPair&) = delete;
    RuntimeCredentialPair& operator=(const RuntimeCredentialPair&) = delete;

private:
    struct LoadedCredential {
        std::string value;
        std::chrono::system_clock::time_point modified;
    };

    std::optional<LoadedCredential> load(
        const std::filesystem::path& path,
        std::chrono::system_clock::time_point now,
        bool report_missing) const;
    bool publish_file(const std::filesystem::path& path, std::string_view value) const;
    bool remove_file(const std::filesystem::path& path) const;
    bool ensure_directory() const;
    void report(bool warning, std::string message) const;

    RuntimeCredentialSpec spec_;
    Publish publish_;
    Log log_;
    std::thread worker_;
    std::atomic_bool stopping_ {false};
    std::mutex wakeup_mutex_;
    std::condition_variable wakeup_;
    bool boot_reconciled_ {false};
    std::optional<std::string> active_current_;
    std::optional<std::chrono::system_clock::time_point> active_modified_;
};

} // namespace sx::auth
