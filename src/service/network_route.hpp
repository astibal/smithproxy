#pragma once

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <unistd.h>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <optional>
#include <set>
#include <string>

namespace sx::net::detail {

using RouteInterfaces = std::set<std::uint32_t>;

struct RouteRequest {
    nlmsghdr header{};
    rtmsg route{};
    std::array<unsigned char, 64> attributes{};
};

inline bool set_route_destination(RouteRequest& request, const std::string& destination) {
    alignas(in6_addr) std::array<unsigned char, 16> address{};
    int address_size = 4;
    if(::inet_pton(AF_INET, destination.c_str(), address.data()) == 1) {
        request.route.rtm_family = AF_INET;
    }
    else if(::inet_pton(AF_INET6, destination.c_str(), address.data()) == 1) {
        request.route.rtm_family = AF_INET6;
        address_size = 16;
        if(IN6_IS_ADDR_V4MAPPED(reinterpret_cast<const in6_addr*>(address.data()))) {
            std::memmove(address.data(), address.data() + 12, 4);
            request.route.rtm_family = AF_INET;
            address_size = 4;
        }
    }
    else {
        return false;
    }

    request.route.rtm_dst_len = address_size * 8;
    const auto offset = NLMSG_ALIGN(request.header.nlmsg_len);
    auto* attribute = reinterpret_cast<rtattr*>(
        reinterpret_cast<unsigned char*>(&request) + offset);
    attribute->rta_type = RTA_DST;
    attribute->rta_len = RTA_LENGTH(address_size);
    std::memcpy(RTA_DATA(attribute), address.data(), address_size);
    request.header.nlmsg_len = offset + RTA_ALIGN(attribute->rta_len);
    return true;
}

inline bool collect_multipath_interfaces(const rtattr& attribute, RouteInterfaces& indices) {
    int remaining = RTA_PAYLOAD(&attribute);
    const auto* hop = static_cast<const rtnexthop*>(RTA_DATA(&attribute));
    while(RTNH_OK(hop, remaining)) {
        const bool unavailable = hop->rtnh_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN);
        if(hop->rtnh_ifindex > 0 && !unavailable) {
            indices.insert(hop->rtnh_ifindex);
        }
        remaining -= RTNH_ALIGN(hop->rtnh_len);
        hop = RTNH_NEXT(hop);
    }
    return remaining == 0;
}

inline bool collect_route_interfaces(const nlmsghdr& header, bool lookup,
                                     RouteInterfaces& indices) {
    const auto* route = static_cast<const rtmsg*>(NLMSG_DATA(&header));
    int remaining = RTM_PAYLOAD(&header);
    for(auto* attribute = RTM_RTA(route); RTA_OK(attribute, remaining);
        attribute = RTA_NEXT(attribute, remaining)) {
        if(attribute->rta_type == RTA_OIF &&
           RTA_PAYLOAD(attribute) == sizeof(std::uint32_t)) {
            std::uint32_t index;
            std::memcpy(&index, RTA_DATA(attribute), sizeof index);
            if(index != 0) {
                indices.insert(index);
            }
        }

        // Nexthop objects require a separate resolver. Never silently
        // label their uplinks Inside when the dump lacks an OIF.
        if(!lookup && attribute->rta_type == RTA_NH_ID) {
            return false;
        }
        if(!lookup && attribute->rta_type == RTA_MULTIPATH &&
           !collect_multipath_interfaces(*attribute, indices)) {
            return false;
        }
    }
    return remaining == 0;
}

enum class RouteReplyStatus { pending, complete, invalid };

inline RouteReplyStatus process_route_reply(const nlmsghdr& header, bool lookup,
                                            RouteInterfaces& indices) {
    if(header.nlmsg_seq != 1) {
        return RouteReplyStatus::pending;
    }
    if((header.nlmsg_flags & NLM_F_DUMP_INTR) || header.nlmsg_type == NLMSG_ERROR) {
        return RouteReplyStatus::invalid;
    }
    if(header.nlmsg_type == NLMSG_DONE) {
        if(NLMSG_PAYLOAD(&header, 0) >= sizeof(int)) {
            int error = 0;
            std::memcpy(&error, NLMSG_DATA(&header), sizeof error);
            if(error != 0) {
                return RouteReplyStatus::invalid;
            }
        }
        return RouteReplyStatus::complete;
    }
    if(header.nlmsg_type != RTM_NEWROUTE ||
       header.nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) {
        return RouteReplyStatus::invalid;
    }

    const auto* route = static_cast<const rtmsg*>(NLMSG_DATA(&header));
    if(lookup) {
        if(route->rtm_type != RTN_UNICAST && route->rtm_type != RTN_LOCAL) {
            return RouteReplyStatus::invalid;
        }
    }
    else if(route->rtm_dst_len != 0 || route->rtm_type != RTN_UNICAST) {
        return RouteReplyStatus::pending;
    }

    if(!collect_route_interfaces(header, lookup, indices)) {
        return RouteReplyStatus::invalid;
    }
    return lookup ? RouteReplyStatus::complete : RouteReplyStatus::pending;
}

inline bool wait_for_route_reply(int fd, std::chrono::steady_clock::time_point deadline) {
    for(;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if(remaining <= 0) {
            return false;
        }
        pollfd poller{fd, POLLIN, 0};
        const int ready = ::poll(&poller, 1, static_cast<int>(remaining));
        if(ready < 0 && errno == EINTR) {
            continue;
        }
        return ready > 0 && (poller.revents & POLLIN);
    }
}

// Private socket per request: replies cannot be consumed by the monitor or
// another worker. Bound the complete exchange, including interrupted polls.
inline std::optional<RouteInterfaces> query_routes(const std::string* destination) {
    RouteRequest request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | (destination ? 0 : NLM_F_DUMP);
    request.header.nlmsg_seq = 1;
    request.route.rtm_family = AF_UNSPEC;
    if(destination && !set_route_destination(request, *destination)) {
        return std::nullopt;
    }

    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if(fd < 0) {
        return std::nullopt;
    }
    struct SocketGuard {
        int fd;
        ~SocketGuard() { ::close(fd); }
    } guard{fd};

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if(::sendto(fd, &request, request.header.nlmsg_len, 0,
                reinterpret_cast<sockaddr*>(&kernel), sizeof kernel) < 0) {
        return std::nullopt;
    }

    RouteInterfaces indices;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    for(;;) {
        if(!wait_for_route_reply(fd, deadline)) {
            return std::nullopt;
        }

        alignas(nlmsghdr) std::array<unsigned char, 65536> data{};
        sockaddr_nl sender{};
        iovec io{data.data(), data.size()};
        msghdr message{};
        message.msg_name = &sender;
        message.msg_namelen = sizeof sender;
        message.msg_iov = &io;
        message.msg_iovlen = 1;
        const auto count = ::recvmsg(fd, &message, 0);
        if(count < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        if(count <= 0 || (message.msg_flags & MSG_TRUNC) || sender.nl_pid != 0) {
            return std::nullopt;
        }

        int remaining = static_cast<int>(count);
        for(auto* header = reinterpret_cast<nlmsghdr*>(data.data()); NLMSG_OK(header, remaining);
            header = NLMSG_NEXT(header, remaining)) {
            switch(process_route_reply(*header, destination != nullptr, indices)) {
                case RouteReplyStatus::complete:
                    return indices;
                case RouteReplyStatus::invalid:
                    return std::nullopt;
                case RouteReplyStatus::pending:
                    break;
            }
        }
        if(remaining != 0) {
            return std::nullopt;
        }
    }
}

} // namespace sx::net::detail
