#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <sys/types.h>

#include <service/cli/cli_broker.hpp>

namespace sx::comm::api {

struct Profile {
    std::string listen_address;
    std::uint16_t listen_port = 55555;
    std::vector<std::string> allowed_ips{"*"};
    std::string bind_interface;
};

int start_internal_broker(Profile profile);
int prepare_external_ingress(const std::string& path);
int stop_broker();
int ingress_fd();
pid_t internal_broker_pid() noexcept;
void set_internal_failure_handler(std::function<void()> handler);
sx::comm::stream::Stats stats() noexcept;
bool uses_external_broker() noexcept;
std::string external_path();

} // namespace sx::comm::api
