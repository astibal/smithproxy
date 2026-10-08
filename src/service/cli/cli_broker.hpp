#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

#include <sys/types.h>

namespace sx::comm::cli {

struct BrokerConfig {
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 50000;
    std::string comm_path;
};

class DuplexRelay {
public:
    int run(int left, int right, const std::atomic<bool>& stop) const;
};

class CliBrokerServer {
public:
    explicit CliBrokerServer(BrokerConfig config): config_(std::move(config)) {}
    int run();

private:
    BrokerConfig config_;
};

int start_internal_broker(std::uint16_t port);
int prepare_external_ingress(const std::string& path);
int stop_broker();
int ingress_fd();
bool receive_handshake(int fd, int timeout_ms = 5000);
void set_internal_failure_handler(std::function<void()> handler);
pid_t internal_broker_pid() noexcept;

} // namespace sx::comm::cli
