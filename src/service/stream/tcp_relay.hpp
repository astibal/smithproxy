#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sx::comm::stream {

struct TcpRelayConfig {
    std::string comm_path;
    std::string destination_host;
    std::uint16_t destination_port = 0;
    std::string bind_interface;
    std::size_t max_active_sessions = 256;
    int connect_timeout_ms = 5000;
    int idle_timeout_ms = 90000;
};

struct TcpRelayStats {
    std::uint64_t accepted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t upstream_connect_errors = 0;
    std::uint64_t active = 0;
    std::uint64_t peak_active = 0;
    std::uint64_t completed = 0;
    std::uint64_t relay_errors = 0;
    std::uint64_t bytes_to_upstream = 0;
    std::uint64_t bytes_from_upstream = 0;
};

class TcpRelaySharedStats;

class TcpRelayServer {
public:
    explicit TcpRelayServer(TcpRelayConfig config, TcpRelaySharedStats* stats = nullptr)
        : config_(std::move(config)), stats_(stats) {}
    int run();
    int run_until(std::atomic<bool>& stop);

private:
    TcpRelayConfig config_;
    TcpRelaySharedStats* stats_ = nullptr;
};

TcpRelaySharedStats* create_tcp_relay_shared_stats();
void destroy_tcp_relay_shared_stats(TcpRelaySharedStats* stats);
TcpRelayStats tcp_relay_snapshot(const TcpRelaySharedStats* stats) noexcept;

} // namespace sx::comm::stream
