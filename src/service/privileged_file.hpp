#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <sys/types.h>

#include <privileged_socket.hpp>

namespace sx::privsep::files {

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
};

// The wire format is intentionally small and is strongly inspired by Socle's
// privileged socket protocol.  The Smithproxy dispatcher is separate: socket
// operations need a fixed fast path, while application capabilities need an
// extensible registry with independently testable handlers.
struct Request {
    std::uint8_t opcode = 0;
    std::string payload;
    int fd = -1; // borrowed for the duration of execute()
};

struct Reply {
    int status = 0;
    std::string payload;
    int fd = -1; // transferred to Server, which closes it after sendmsg()
};

class Operation {
public:
    virtual ~Operation() = default;
    virtual Reply execute(const Request& request) = 0;
    virtual void shutdown() noexcept {}
};

class Client {
public:
    explicit Client(int fd, std::chrono::milliseconds timeout = std::chrono::seconds(90));

    int ping();
    int config_read(std::string& output);
    int config_write(const std::string& content);
    int config_backup(const std::string& version, const std::string& content);
    int pid_exists(bool& output);
    int pid_write(pid_t pid);
    int pid_remove();

    // Extension point for specialized clients. Built-in wrappers above remain
    // the preferred API for the standard operations.
    int request(std::uint8_t opcode, const std::string& payload, int passed_fd,
                Reply& response);

private:
    int transact(std::uint8_t opcode, const std::string& payload, int passed_fd,
                 socle::privsep::Message& response);
    int wait_readable() const;
    void break_channel() noexcept;

    socle::privsep::SeqPacketChannel channel_;
    std::chrono::milliseconds timeout_;
    std::mutex mutex_;
    bool broken_ = false;
};

class Server {
public:
    Server(int fd, Targets targets);
    virtual ~Server();

    int run();
    int serve_once();

    // Registration is complete before run() starts. Sharing one Operation
    // across several opcodes is supported (for capability families).
    int register_operation(std::uint8_t opcode, std::shared_ptr<Operation> operation);
    int register_operation(Opcode opcode, std::shared_ptr<Operation> operation) {
        return register_operation(static_cast<std::uint8_t>(opcode), std::move(operation));
    }

private:
    void register_default_operations(const Targets& targets);
    int dispatch(socle::privsep::Message& request);
    int respond(std::uint8_t opcode, Reply reply);
    void shutdown_operations() noexcept;

    socle::privsep::SeqPacketChannel channel_;
    std::unordered_map<std::uint8_t, std::shared_ptr<Operation>> operations_;
    bool running_ = false;
    bool shutdown_complete_ = false;
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
int pid_exists(const std::string& path, bool& output);
int pid_write(const std::string& path, pid_t pid);
int pid_remove(const std::string& path);

} // namespace sx::privsep::files
