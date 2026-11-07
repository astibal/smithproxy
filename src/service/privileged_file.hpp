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
    explicit Client(int fd, std::chrono::milliseconds timeout = std::chrono::seconds(90));

    int ping();
    int config_read(std::string& output);
    int config_write(const std::string& content);
    int config_backup(const std::string& version, const std::string& content);
    int config_backup_read(const std::string& version, std::string& output);
    int pid_exists(bool& output);
    int pid_write(pid_t pid);
    int pid_remove();

};

class Server : public sx::comm::Server {
public:
    Server(int fd, Targets targets);
    int register_operation(Opcode opcode, std::shared_ptr<Operation> operation) {
        return sx::comm::Server::register_operation(static_cast<std::uint8_t>(opcode),
                                                    std::move(operation));
    }
    using sx::comm::Server::register_operation;
};

int read_file(const std::string& path, std::string& output);
int write_file_atomic(const std::string& path, const std::string& content);
int write_backup_atomic(const std::string& path, const std::string& version,
                        const std::string& content);

int start_local_helper(Targets targets);
int stop_local_helper();

int config_read(const std::string& path, std::string& output);
int config_write(const std::string& path, const std::string& content);
int config_backup(const std::string& path, const std::string& version,
                  const std::string& content);
int config_backup_read(const std::string& path, const std::string& version,
                       std::string& output);
int pid_exists(const std::string& path, bool& output);
int pid_write(const std::string& path, pid_t pid);
int pid_remove(const std::string& path);

} // namespace sx::privsep::files
