#pragma once

#include <cstdint>
#include <memory>
#include <string>

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
    std::uint64_t exported = 0;
    std::uint64_t errors = 0;
};

int start_local_broker(Profile profile);
int stop_local_broker();
std::shared_ptr<socle::traflog::GreTransport> transport();
Stats stats() noexcept;

} // namespace sx::comm::gre
