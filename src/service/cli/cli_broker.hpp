#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <sys/types.h>

namespace sx::comm::stream {

struct BrokerConfig {
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 50000;
    std::string comm_path;
    std::string preamble;
    std::vector<std::string> allowed_ips{"*"};
    std::string bind_interface;
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
            SharedStats* stats = nullptr) const;
};

class BrokerServer {
public:
    explicit BrokerServer(BrokerConfig config, SharedStats* stats = nullptr)
        : config_(std::move(config)), stats_(stats) {}
    int run();

private:
    BrokerConfig config_;
    SharedStats* stats_ = nullptr;
};

int create_unix_listener(const std::string& path);
SharedStats* create_shared_stats();
void destroy_shared_stats(SharedStats* stats);
Stats snapshot(const SharedStats* stats) noexcept;

} // namespace sx::comm::stream

namespace sx::comm::cli {

using DuplexRelay = sx::comm::stream::DuplexRelay;
using CliBrokerServer = sx::comm::stream::BrokerServer;
using BrokerConfig = sx::comm::stream::BrokerConfig;

std::string handshake();

int start_internal_broker(std::uint16_t port);
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
