#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <string_view>

#include <arpa/inet.h>
#include <sys/socket.h>

namespace sx::proxy::local_destination {

enum class peer_status {
    allowed,
    blocked,
    unavailable,
};

inline bool prohibited_ipv4(const in_addr& address) noexcept {
    const auto host_order = ntohl(address.s_addr);
    return host_order == INADDR_ANY || (host_order >> 24U) == IN_LOOPBACKNET;
}

inline bool prohibited_ipv6(const in6_addr& address) noexcept {
    if(IN6_IS_ADDR_UNSPECIFIED(&address) || IN6_IS_ADDR_LOOPBACK(&address))
        return true;

    // IPv4-mapped IPv6 addresses must follow the IPv4 rules as well. Without
    // this normalization, ::ffff:127.0.0.1 bypasses a textual IPv6 check.
    if(IN6_IS_ADDR_V4MAPPED(&address)) {
        in_addr mapped {};
        std::memcpy(&mapped, address.s6_addr + 12, sizeof(mapped));
        return prohibited_ipv4(mapped);
    }

    return false;
}

inline bool prohibited(const sockaddr* address, socklen_t size) noexcept {
    if(address == nullptr) return false;

    if(address->sa_family == AF_INET && size >= sizeof(sockaddr_in)) {
        auto const* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        return prohibited_ipv4(ipv4->sin_addr);
    }

    if(address->sa_family == AF_INET6 && size >= sizeof(sockaddr_in6)) {
        auto const* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        return prohibited_ipv6(ipv6->sin6_addr);
    }

    return false;
}

inline bool prohibited(std::string_view text) noexcept {
    if(text.empty() || text.size() >= INET6_ADDRSTRLEN) return false;

    std::array<char, INET6_ADDRSTRLEN> terminated {};
    std::memcpy(terminated.data(), text.data(), text.size());

    sockaddr_in ipv4 {};
    ipv4.sin_family = AF_INET;
    if(::inet_pton(AF_INET, terminated.data(), &ipv4.sin_addr) == 1)
        return prohibited(reinterpret_cast<const sockaddr*>(&ipv4), sizeof(ipv4));

    sockaddr_in6 ipv6 {};
    ipv6.sin6_family = AF_INET6;
    if(::inet_pton(AF_INET6, terminated.data(), &ipv6.sin6_addr) == 1)
        return prohibited(reinterpret_cast<const sockaddr*>(&ipv6), sizeof(ipv6));

    return false;
}

inline peer_status inspect_connected_peer(int socket) noexcept {
    sockaddr_storage peer {};
    socklen_t peer_size = sizeof(peer);
    if(socket < 0 || ::getpeername(
            socket, reinterpret_cast<sockaddr*>(&peer), &peer_size) != 0) {
        return peer_status::unavailable;
    }

    if(peer.ss_family != AF_INET && peer.ss_family != AF_INET6)
        return peer_status::unavailable;

    return prohibited(reinterpret_cast<const sockaddr*>(&peer), peer_size)
        ? peer_status::blocked
        : peer_status::allowed;
}

} // namespace sx::proxy::local_destination
