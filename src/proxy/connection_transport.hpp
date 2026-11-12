#pragma once

#include <basecom.hpp>
#include <nlohmann/json.hpp>

namespace sx::proxy {

// Event metadata describes the physical carrier, not the logical I/O facade.
// In particular, a QUIC stream has stream I/O semantics but travels over UDP.
// Leave unknown carriers absent rather than guessing TCP.
inline void add_connection_transport(nlohmann::json& info, baseCom const& com) {
    const auto type = com.policy_l4_proto();
    if (type == SOCK_STREAM) info["transport"] = "tcp";
    else if (type == SOCK_DGRAM) info["transport"] = "udp";
}

} // namespace sx::proxy
