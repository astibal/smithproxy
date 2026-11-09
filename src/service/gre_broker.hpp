#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <sys/types.h>

#include <traflog/pcaplog.hpp>

namespace sx::comm::gre {

struct Profile {
    int family = AF_INET;
    std::string destination;
    int ttl = 1;
    std::string bind_interface;
};

struct Stats {
    std::uint64_t submitted = 0;
    std::uint64_t dropped = 0;
    std::uint64_t received = 0;
    std::uint64_t exported = 0;
    std::uint64_t errors = 0;
    std::uint64_t reconnects = 0;
    bool connected = false;
};

enum class Mode { disabled, internal, external };

int start_local_broker(Profile profile);
int connect_external_broker(const std::string& path);
int stop_local_broker();
int run_standalone_broker(const std::string& path, Profile profile);
void set_internal_failure_handler(std::function<void()> handler);
std::shared_ptr<socle::traflog::GreTransport> transport();
Stats stats() noexcept;
int broker_stats(Stats& output);
Mode mode() noexcept;
std::string external_path();
pid_t owned_broker_pid() noexcept;

} // namespace sx::comm::gre
