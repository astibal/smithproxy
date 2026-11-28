#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <sys/types.h>

namespace sx::comm::stream {

struct BrokerConfig {
    BrokerConfig() = default;
    BrokerConfig(std::string address, std::uint16_t port, std::string core_path,
                 std::string core_preamble, std::vector<std::string> permitted_ips,
                 std::string interface, std::size_t session_limit)
        : listen_address(std::move(address)), listen_port(port),
          comm_path(std::move(core_path)), preamble(std::move(core_preamble)),
          allowed_ips(std::move(permitted_ips)), bind_interface(std::move(interface)),
          max_active_sessions(session_limit) {}

    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 50000;
    std::string comm_path;
    std::string preamble;
    std::vector<std::string> allowed_ips{"*"};
    std::string bind_interface;
    std::size_t max_active_sessions = 256;
    std::string unix_socket_path;
    std::vector<uid_t> allowed_unix_uids;
    uid_t unix_socket_owner = static_cast<uid_t>(-1);
    gid_t unix_socket_group = static_cast<gid_t>(-1);
    bool tcp_enabled = true;
};

struct Stats {
    std::uint64_t accepted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t core_connect_errors = 0;
    std::uint64_t active = 0;
    std::uint64_t peak_active = 0;
    std::uint64_t completed = 0;
    std::uint64_t relay_errors = 0;
    std::uint64_t bytes_to_core = 0;
    std::uint64_t bytes_from_core = 0;
};

class SharedStats;

class DuplexRelay {
public:
    int run(int left, int right, const std::atomic<bool>& stop,
            SharedStats* stats = nullptr,
            std::atomic<std::uint64_t>* bytes_left_to_right = nullptr,
            std::atomic<std::uint64_t>* bytes_right_to_left = nullptr,
            int idle_timeout_ms = 0) const;
};

class BrokerServer {
public:
    explicit BrokerServer(BrokerConfig config, SharedStats* stats = nullptr)
        : config_(std::move(config)), stats_(stats) {}
    int run(int stop_fd = -1);

private:
    BrokerConfig config_;
    SharedStats* stats_ = nullptr;
};

int create_unix_listener(const std::string& path);
SharedStats* create_shared_stats();
void destroy_shared_stats(SharedStats* stats);
Stats snapshot(const SharedStats* stats) noexcept;

// Validate kernel-supplied Unix peer identity. A usable process ID and an
// explicitly trusted effective UID are both required.
bool unix_peer_allowed(pid_t peer_pid, uid_t peer_uid,
                       const std::vector<uid_t>& allowed_uids) noexcept;

} // namespace sx::comm::stream

namespace sx::comm::cli {

using DuplexRelay = sx::comm::stream::DuplexRelay;
using CliBrokerServer = sx::comm::stream::BrokerServer;
using BrokerConfig = sx::comm::stream::BrokerConfig;

std::string handshake();

int start_internal_broker(
    std::uint16_t port,
    std::string public_socket_path = {},
    uid_t public_socket_owner = static_cast<uid_t>(-1),
    gid_t public_socket_group = static_cast<gid_t>(-1),
    bool console_enabled = true);
int prepare_external_ingress(const std::string& path);
int stop_broker();
int ingress_fd();
bool receive_handshake(int fd, int timeout_ms = 5000);
void set_internal_failure_handler(std::function<void()> handler);
pid_t internal_broker_pid() noexcept;
sx::comm::stream::Stats stats() noexcept;
bool uses_external_broker() noexcept;
std::string external_path();

} // namespace sx::comm::cli
