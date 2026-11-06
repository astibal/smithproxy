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
// Private socket per request: replies cannot be consumed by the monitor or
// another worker. Bound the complete exchange, including interrupted polls.
inline std::optional<std::set<std::uint32_t>> query_routes(const std::string* destination) {
    struct Request { nlmsghdr header; rtmsg route; std::array<unsigned char, 64> attrs; } req{};
    req.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    req.header.nlmsg_type = RTM_GETROUTE;
    req.header.nlmsg_flags = NLM_F_REQUEST | (destination ? 0 : NLM_F_DUMP);
    req.header.nlmsg_seq = 1;
    req.route.rtm_family = AF_UNSPEC;
    if(destination) {
        alignas(in6_addr) std::array<unsigned char, 16> bytes{};
        int size = 4;
        if(::inet_pton(AF_INET, destination->c_str(), bytes.data()) == 1) req.route.rtm_family = AF_INET;
        else if(::inet_pton(AF_INET6, destination->c_str(), bytes.data()) == 1) {
            req.route.rtm_family = AF_INET6;
            size = 16;
            if(IN6_IS_ADDR_V4MAPPED(reinterpret_cast<const in6_addr*>(bytes.data()))) {
                std::memmove(bytes.data(), bytes.data()+12, 4);
                req.route.rtm_family = AF_INET;
                size = 4;
            }
        } else return std::nullopt;
        req.route.rtm_dst_len = size * 8;
        auto* attr = reinterpret_cast<rtattr*>(reinterpret_cast<unsigned char*>(&req) + NLMSG_ALIGN(req.header.nlmsg_len));
        attr->rta_type = RTA_DST;
        attr->rta_len = RTA_LENGTH(size);
        std::memcpy(RTA_DATA(attr), bytes.data(), size);
        req.header.nlmsg_len = NLMSG_ALIGN(req.header.nlmsg_len) + RTA_ALIGN(attr->rta_len);
    }
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if(fd < 0) return std::nullopt;
    struct Guard { int fd; ~Guard() { ::close(fd); } } guard{fd};
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if(::sendto(fd, &req, req.header.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof kernel) < 0) return std::nullopt;
    std::set<std::uint32_t> indices;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    for(;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if(remaining <= 0) return std::nullopt;
        pollfd poller{fd, POLLIN, 0};
        const int ready = ::poll(&poller, 1, static_cast<int>(remaining));
        if(ready < 0 && errno == EINTR) continue;
        if(ready <= 0 || !(poller.revents & POLLIN)) return std::nullopt;
        alignas(nlmsghdr) std::array<unsigned char, 65536> data{};
        sockaddr_nl sender{};
        iovec io{data.data(), data.size()};
        msghdr msg{};
        msg.msg_name = &sender; msg.msg_namelen = sizeof sender;
        msg.msg_iov = &io; msg.msg_iovlen = 1;
        const auto count = ::recvmsg(fd, &msg, 0);
        if(count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if(count <= 0 || msg.msg_flags & MSG_TRUNC || sender.nl_pid != 0) return std::nullopt;
        int length = static_cast<int>(count);
        for(auto* h = reinterpret_cast<nlmsghdr*>(data.data()); NLMSG_OK(h, length); h = NLMSG_NEXT(h, length)) {
            if(h->nlmsg_seq != 1) continue;
            if(h->nlmsg_flags & NLM_F_DUMP_INTR) return std::nullopt;
            if(h->nlmsg_type == NLMSG_ERROR) return std::nullopt;
            if(h->nlmsg_type == NLMSG_DONE) {
                if(NLMSG_PAYLOAD(h, 0) >= sizeof(int)) {
                    int error = 0; std::memcpy(&error, NLMSG_DATA(h), sizeof error);
                    if(error) return std::nullopt;
                }
                return indices;
            }
            if(h->nlmsg_type != RTM_NEWROUTE || h->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) return std::nullopt;
            const auto* route = static_cast<const rtmsg*>(NLMSG_DATA(h));
            if(destination) {
                if(route->rtm_type != RTN_UNICAST && route->rtm_type != RTN_LOCAL) return std::nullopt;
            } else if(route->rtm_dst_len != 0 || route->rtm_type != RTN_UNICAST) continue;
            int attrs = RTM_PAYLOAD(h);
            for(auto* a = RTM_RTA(route); RTA_OK(a, attrs); a = RTA_NEXT(a, attrs)) {
                if(a->rta_type == RTA_OIF && RTA_PAYLOAD(a) == sizeof(std::uint32_t)) {
                    std::uint32_t index; std::memcpy(&index, RTA_DATA(a), sizeof index);
                    if(index) indices.insert(index);
                }
                // Nexthop objects require a separate resolver. Never silently
                // label their uplinks Inside when the dump lacks an OIF.
                if(!destination && a->rta_type == RTA_NH_ID) return std::nullopt;
                if(!destination && a->rta_type == RTA_MULTIPATH) {
                    int bytes = RTA_PAYLOAD(a);
                    auto* hop = static_cast<rtnexthop*>(RTA_DATA(a));
                    while(RTNH_OK(hop, bytes)) {
                        if(hop->rtnh_ifindex > 0 && !(hop->rtnh_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN))) indices.insert(hop->rtnh_ifindex);
                        bytes -= RTNH_ALIGN(hop->rtnh_len); hop = RTNH_NEXT(hop);
                    }
                    if(bytes != 0) return std::nullopt;
                }
            }
            if(attrs != 0) return std::nullopt;
            if(destination) return indices;
        }
        if(length != 0) return std::nullopt;
    }
}
}
