#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <sys/types.h>

#include <service/comm.hpp>

namespace sx::privsep::files {

// A serialized CfgTar may contain 256 MiB of resource data plus deterministic
// TAR headers. Keep the privileged transport bound finite but large enough for
// every archive accepted by CfgTar.
constexpr std::size_t max_config_payload = 272U * 1024U * 1024U;

struct Targets {
    std::string config;
    std::string pid;
};

enum class Opcode : std::uint8_t {
    Ping = 1,
    ConfigRead = 2,
    ConfigWrite = 3,
    ConfigBackup = 4,
    PidExists = 5,
    PidWrite = 6,
    PidRemove = 7,
    ConfigBackupRead = 8,
    ConfigInstall = 9,
};

// The wire format is intentionally small and is strongly inspired by Socle's
// privileged socket protocol.  The Smithproxy dispatcher is separate: socket
// operations need a fixed fast path, while application capabilities need an
// extensible registry with independently testable handlers.
using Request = sx::comm::Request;
using Reply = sx::comm::Reply;
using Operation = sx::comm::Operation;

class Client : public sx::comm::Client {
public:
    // Bind the typed file protocol to an already connected private channel.
    explicit Client(int fd, std::chrono::milliseconds timeout = std::chrono::seconds(90));

    // Verify that the privileged helper is alive and speaks this protocol.
    int ping();
    // Read the configured startup file through the privileged helper.
    int config_read(std::string& output);
    // Atomically replace the configured startup file without a generation check.
    int config_write(const std::string& content);
    // Install replacement only when the current file still equals expected.
    int config_install(const std::string& expected, const std::string& replacement);
    // Atomically write a named recovery copy beside the configured file.
    int config_backup(const std::string& version, const std::string& content);
    // Read one named recovery copy through the privileged helper.
    int config_backup_read(const std::string& version, std::string& output);
    // Report whether the helper-owned PID file currently exists.
    int pid_exists(bool& output);
    // Create and claim the PID file for this helper lifetime.
    int pid_write(pid_t pid);
    // Remove the PID file only when this helper still owns its inode.
    int pid_remove();

};

class Server : public sx::comm::Server {
public:
    // Register fixed config and PID capabilities on one private channel.
    Server(int fd, Targets targets);
    // Register a typed file opcode through the generic capability registry.
    int register_operation(Opcode opcode, std::shared_ptr<Operation> operation) {
        return sx::comm::Server::register_operation(static_cast<std::uint8_t>(opcode),
                                                    std::move(operation));
    }
    using sx::comm::Server::register_operation;
};

// Read one bounded regular file without following a final symlink.
int read_file(const std::string& path, std::string& output);
// Atomically replace one explicit path while preserving existing permissions.
int write_file_atomic(const std::string& path, const std::string& content);
// Atomically write one validated backup suffix beside an explicit path.
int write_backup_atomic(const std::string& path, const std::string& version,
                        const std::string& content);

// Fork and connect the local privileged helper for the configured targets.
int start_local_helper(Targets targets);
// Close the helper channel, wait for exit and release installed capabilities.
int stop_local_helper();

// Route a config read through the helper, or perform it directly before setup.
int config_read(const std::string& path, std::string& output);
// Route an unconditional atomic config replacement through the helper.
int config_write(const std::string& path, const std::string& content);
// Replace one configuration only if its current bytes still match expected.
// The privileged helper holds the shared CFtar sidecar lock while it writes
// the recovery copy and publishes the replacement.
int config_install(const std::string& path, const std::string& expected,
                   const std::string& replacement);
// Route a named recovery write through the helper.
int config_backup(const std::string& path, const std::string& version,
                  const std::string& content);
// Route a named recovery read through the helper.
int config_backup_read(const std::string& path, const std::string& version,
                       std::string& output);
// Route a PID existence query through the helper.
int pid_exists(const std::string& path, bool& output);
// Route creation of the helper-owned PID file.
int pid_write(const std::string& path, pid_t pid);
// Route removal of the helper-owned PID file.
int pid_remove(const std::string& path);

} // namespace sx::privsep::files
