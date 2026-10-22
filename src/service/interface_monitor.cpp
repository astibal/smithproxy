#include <service/interface_monitor.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <limits>
#include <tuple>
#include <utility>

#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sx::net {
namespace {

constexpr std::size_t netlink_buffer_size = 64U * 1024U;

enum class EventKind {
    new_link,
    delete_link,
    new_address,
    delete_address,
};

struct ParsedEvent {
    EventKind kind = EventKind::new_link;
    InterfaceInfo interface;
    InterfaceAddress address;
    std::string address_label;
};

bool same_interface(const InterfaceInfo& left, const InterfaceInfo& right) {
    return left.index == right.index && left.name == right.name && left.flags == right.flags;
}

bool same_address(const InterfaceAddress& left, const InterfaceAddress& right) {
    return left.interface_index == right.interface_index &&
           left.family == right.family && left.address == right.address &&
           left.address_size == right.address_size &&
           left.prefix_length == right.prefix_length && left.scope == right.scope &&
           left.flags == right.flags;
}

std::string attribute_string(const rtattr* attribute) {
    const auto size = static_cast<std::size_t>(RTA_PAYLOAD(attribute));
    const auto* data = static_cast<const char*>(RTA_DATA(attribute));
    return std::string(data, ::strnlen(data, size));
}

bool copy_address_attribute(const rtattr* attribute, int family,
                            std::array<std::uint8_t, 16>& output,
                            std::uint8_t& output_size) {
    std::size_t expected = 0;
    if(family == AF_INET) expected = 4;
    else if(family == AF_INET6) expected = 16;
    else return false;

    if(static_cast<std::size_t>(RTA_PAYLOAD(attribute)) < expected) return false;
    output.fill(0);
    std::memcpy(output.data(), RTA_DATA(attribute), expected);
    output_size = static_cast<std::uint8_t>(expected);
    return true;
}

bool parse_link(const nlmsghdr* header, ParsedEvent& event, std::string& error) {
    if(header->nlmsg_len < NLMSG_LENGTH(sizeof(ifinfomsg))) {
        error = "short rtnetlink link message";
        return false;
    }

    const auto* info = static_cast<const ifinfomsg*>(NLMSG_DATA(header));
    if(info->ifi_index <= 0) {
        error = "rtnetlink link message has invalid interface index";
        return false;
    }

    event.kind = header->nlmsg_type == RTM_NEWLINK
        ? EventKind::new_link : EventKind::delete_link;
    event.interface.index = static_cast<std::uint32_t>(info->ifi_index);
    event.interface.flags = info->ifi_flags;

    int remaining = static_cast<int>(header->nlmsg_len) -
                    static_cast<int>(NLMSG_LENGTH(sizeof(ifinfomsg)));
    for(auto* attribute = IFLA_RTA(info); RTA_OK(attribute, remaining);
        attribute = RTA_NEXT(attribute, remaining)) {
        if(attribute->rta_type == IFLA_IFNAME) {
            event.interface.name = attribute_string(attribute);
        }
    }
    if(remaining != 0) {
        error = "malformed rtnetlink link attributes";
        return false;
    }
    if(event.kind == EventKind::new_link && event.interface.name.empty()) {
        error = "rtnetlink link message is missing IFLA_IFNAME";
        return false;
    }
    return true;
}

bool parse_address(const nlmsghdr* header, ParsedEvent& event, std::string& error) {
    if(header->nlmsg_len < NLMSG_LENGTH(sizeof(ifaddrmsg))) {
        error = "short rtnetlink address message";
        return false;
    }

    const auto* info = static_cast<const ifaddrmsg*>(NLMSG_DATA(header));
    if(info->ifa_index == 0 || (info->ifa_family != AF_INET && info->ifa_family != AF_INET6)) {
        error = "rtnetlink address message has an unsupported family or interface index";
        return false;
    }

    event.kind = header->nlmsg_type == RTM_NEWADDR
        ? EventKind::new_address : EventKind::delete_address;
    event.address.interface_index = info->ifa_index;
    event.address.family = info->ifa_family;
    event.address.prefix_length = info->ifa_prefixlen;
    event.address.scope = info->ifa_scope;
    event.address.flags = info->ifa_flags;

    const rtattr* local = nullptr;
    const rtattr* address = nullptr;
    int remaining = static_cast<int>(header->nlmsg_len) -
                    static_cast<int>(NLMSG_LENGTH(sizeof(ifaddrmsg)));
    for(auto* attribute = IFA_RTA(info); RTA_OK(attribute, remaining);
        attribute = RTA_NEXT(attribute, remaining)) {
        switch(attribute->rta_type) {
            case IFA_LOCAL:
                local = attribute;
                break;
            case IFA_ADDRESS:
                address = attribute;
                break;
            case IFA_LABEL:
                event.address_label = attribute_string(attribute);
                break;
            case IFA_FLAGS:
                if(RTA_PAYLOAD(attribute) >= sizeof(std::uint32_t)) {
                    std::memcpy(&event.address.flags, RTA_DATA(attribute),
                                sizeof(event.address.flags));
                }
                break;
            default:
                break;
        }
    }
    if(remaining != 0) {
        error = "malformed rtnetlink address attributes";
        return false;
    }

    // IFA_LOCAL is the local endpoint of a point-to-point IPv4 address;
    // IFA_ADDRESS can be its peer. IPv6 normally supplies IFA_ADDRESS only.
    const rtattr* selected = local != nullptr ? local : address;
    if(selected == nullptr ||
       !copy_address_attribute(selected, event.address.family,
                               event.address.address, event.address.address_size)) {
        error = "rtnetlink address message has no valid local address";
        return false;
    }
    return true;
}

struct ParsedBatch {
    detail::NetlinkBatchResult result;
    std::vector<ParsedEvent> events;
};

ParsedBatch parse_datagram(const void* data, std::size_t size,
                           std::uint32_t expected_sequence) {
    ParsedBatch output;
    if(data == nullptr || size == 0 || size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        output.result.ok = false;
        output.result.error_code = EINVAL;
        output.result.error = "invalid rtnetlink datagram";
        return output;
    }

    int remaining = static_cast<int>(size);
    for(auto* header = static_cast<const nlmsghdr*>(data); NLMSG_OK(header, remaining);
        header = NLMSG_NEXT(header, remaining)) {
        const bool matching_sequence = expected_sequence == 0 ||
                                       header->nlmsg_seq == expected_sequence;
        if(header->nlmsg_type == NLMSG_DONE) {
            if(matching_sequence) {
                if(header->nlmsg_len >= NLMSG_LENGTH(sizeof(int))) {
                    int dump_error = 0;
                    std::memcpy(&dump_error, NLMSG_DATA(header), sizeof(dump_error));
                    if(dump_error < 0) {
                        output.result.ok = false;
                        output.result.error_code = -dump_error;
                        output.result.error = std::string("rtnetlink dump failed: ") +
                                              std::strerror(output.result.error_code);
                        return output;
                    }
                }
                output.result.done = true;
                output.result.dump_interrupted = (header->nlmsg_flags & NLM_F_DUMP_INTR) != 0;
            }
            continue;
        }
        if(header->nlmsg_type == NLMSG_NOOP) continue;
        if(header->nlmsg_type == NLMSG_OVERRUN) {
            output.result.ok = false;
            output.result.error_code = ENOBUFS;
            output.result.error = "rtnetlink reported an overrun";
            return output;
        }
        if(header->nlmsg_type == NLMSG_ERROR) {
            if(header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                output.result.ok = false;
                output.result.error_code = EBADMSG;
                output.result.error = "short rtnetlink error message";
                return output;
            }
            const auto* message = static_cast<const nlmsgerr*>(NLMSG_DATA(header));
            if(message->error != 0 && matching_sequence) {
                output.result.ok = false;
                output.result.error_code = -message->error;
                output.result.error = std::string("rtnetlink request failed: ") +
                                      std::strerror(output.result.error_code);
                return output;
            }
            continue;
        }

        ParsedEvent event;
        bool relevant = true;
        bool parsed = false;
        switch(header->nlmsg_type) {
            case RTM_NEWLINK:
            case RTM_DELLINK:
                parsed = parse_link(header, event, output.result.error);
                break;
            case RTM_NEWADDR:
            case RTM_DELADDR:
                parsed = parse_address(header, event, output.result.error);
                break;
            default:
                relevant = false;
                break;
        }
        if(relevant && !parsed) {
            output.result.ok = false;
            output.result.error_code = EBADMSG;
            return output;
        }
        if(relevant) output.events.push_back(std::move(event));
    }

    if(remaining != 0) {
        output.result.ok = false;
        output.result.error_code = EBADMSG;
        output.result.error = "trailing bytes in rtnetlink datagram";
    }
    return output;
}

int open_route_socket(std::string& error) {
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                            NETLINK_ROUTE);
    if(fd < 0) {
        error = std::string("cannot open NETLINK_ROUTE socket: ") + std::strerror(errno);
        return -1;
    }

    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if(::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        const int saved_errno = errno;
        ::close(fd);
        error = std::string("cannot subscribe NETLINK_ROUTE socket: ") +
                std::strerror(saved_errno);
        return -1;
    }
    return fd;
}

bool send_dump_request(int fd, std::uint16_t type, std::uint32_t sequence,
                       std::string& error) {
    struct Request {
        nlmsghdr header{};
        union {
            ifinfomsg link;
            ifaddrmsg address;
        } payload{};
    } request;

    request.header.nlmsg_type = type;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    if(type == RTM_GETLINK) {
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
        request.payload.link.ifi_family = AF_UNSPEC;
    } else {
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
        request.payload.address.ifa_family = AF_UNSPEC;
    }

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    const auto sent = ::sendto(fd, &request, request.header.nlmsg_len, 0,
                               reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel));
    if(sent != static_cast<ssize_t>(request.header.nlmsg_len)) {
        const int saved_errno = sent < 0 ? errno : EIO;
        error = std::string("cannot request rtnetlink dump: ") + std::strerror(saved_errno);
        return false;
    }
    return true;
}

enum class ReceiveStatus {
    received,
    would_block,
    stopped,
    failed,
};

struct ReceiveResult {
    ReceiveStatus status = ReceiveStatus::failed;
    detail::NetlinkBatchResult batch;
    std::string error;
};

ReceiveResult receive_datagram(int fd, int stop_fd, detail::InterfaceTable& table,
                               std::uint32_t expected_sequence, int timeout_ms) {
    pollfd descriptors[2] = {
        {fd, POLLIN, 0},
        {stop_fd, POLLIN, 0},
    };

    int poll_result;
    do {
        poll_result = ::poll(descriptors, 2, timeout_ms);
    } while(poll_result < 0 && errno == EINTR);
    if(poll_result == 0) return {ReceiveStatus::would_block, {}, {}};
    if(poll_result < 0) {
        return {ReceiveStatus::failed, {},
                std::string("cannot poll rtnetlink socket: ") + std::strerror(errno)};
    }
    if((descriptors[1].revents & (POLLIN | POLLERR | POLLHUP)) != 0) {
        return {ReceiveStatus::stopped, {}, {}};
    }
    if((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        return {ReceiveStatus::failed, {}, "rtnetlink socket reported a poll error"};
    }
    if((descriptors[0].revents & POLLIN) == 0) {
        return {ReceiveStatus::would_block, {}, {}};
    }

    std::array<std::uint8_t, netlink_buffer_size> buffer{};
    sockaddr_nl sender{};
    iovec vector{buffer.data(), buffer.size()};
    msghdr message{};
    message.msg_name = &sender;
    message.msg_namelen = sizeof(sender);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;

    ssize_t received;
    do {
        received = ::recvmsg(fd, &message, MSG_DONTWAIT);
    } while(received < 0 && errno == EINTR);
    if(received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return {ReceiveStatus::would_block, {}, {}};
    }
    if(received < 0) {
        return {ReceiveStatus::failed, {},
                std::string("cannot read rtnetlink socket: ") + std::strerror(errno)};
    }
    if((message.msg_flags & MSG_TRUNC) != 0) {
        return {ReceiveStatus::failed, {}, "truncated rtnetlink datagram"};
    }
    if(sender.nl_family != AF_NETLINK || sender.nl_pid != 0) {
        return {ReceiveStatus::failed, {}, "rtnetlink datagram did not originate in the kernel"};
    }

    auto batch = table.apply_netlink_datagram(buffer.data(),
                                               static_cast<std::size_t>(received),
                                               expected_sequence);
    if(!batch.ok) {
        auto error = batch.error;
        return {ReceiveStatus::failed, std::move(batch), std::move(error)};
    }
    return {ReceiveStatus::received, std::move(batch), {}};
}

enum class SyncStatus {
    ready,
    stopped,
    failed,
};

SyncStatus receive_dump(int fd, int stop_fd, detail::InterfaceTable& table,
                        std::uint16_t request_type, std::uint32_t sequence,
                        std::string& error) {
    if(!send_dump_request(fd, request_type, sequence, error)) return SyncStatus::failed;
    for(;;) {
        auto received = receive_datagram(fd, stop_fd, table, sequence, -1);
        if(received.status == ReceiveStatus::stopped) return SyncStatus::stopped;
        if(received.status == ReceiveStatus::failed) {
            error = std::move(received.error);
            return SyncStatus::failed;
        }
        if(received.status != ReceiveStatus::received) continue;
        if(received.batch.dump_interrupted) {
            error = "rtnetlink dump was interrupted by a concurrent network change";
            return SyncStatus::failed;
        }
        if(received.batch.done) return SyncStatus::ready;
    }
}

SyncStatus synchronize_table(int fd, int stop_fd, detail::InterfaceTable& table,
                             std::uint32_t& sequence, std::string& error) {
    table.clear();
    auto status = receive_dump(fd, stop_fd, table, RTM_GETLINK, ++sequence, error);
    if(status != SyncStatus::ready) return status;
    return receive_dump(fd, stop_fd, table, RTM_GETADDR, ++sequence, error);
}

bool wait_for_retry_or_stop(int stop_fd, int milliseconds) {
    pollfd descriptor{stop_fd, POLLIN, 0};
    int result;
    do {
        result = ::poll(&descriptor, 1, milliseconds);
    } while(result < 0 && errno == EINTR);
    return result > 0;
}

} // namespace

std::string InterfaceAddress::text() const {
    char output[INET6_ADDRSTRLEN]{};
    if((family != AF_INET && family != AF_INET6) ||
       ::inet_ntop(family, address.data(), output, sizeof(output)) == nullptr) {
        return {};
    }
    return output;
}

std::optional<std::string> InterfaceSnapshot::interface_name(std::uint32_t index) const {
    const auto found = std::find_if(interfaces.begin(), interfaces.end(),
                                    [index](const InterfaceInfo& interface) {
                                        return interface.index == index;
                                    });
    if(found == interfaces.end()) return std::nullopt;
    return found->name;
}

bool InterfaceSnapshot::contains_address(int family, const void* candidate,
                                         std::size_t candidate_size) const noexcept {
    if(candidate == nullptr) return false;
    return std::any_of(addresses.begin(), addresses.end(),
                       [family, candidate, candidate_size](const InterfaceAddress& address) {
                           return address.family == family &&
                                  address.address_size == candidate_size &&
                                  std::memcmp(address.address.data(), candidate, candidate_size) == 0;
                       });
}

namespace detail {

bool InterfaceTable::AddressKey::operator<(const AddressKey& other) const noexcept {
    return std::tie(interface_index, family, address) <
           std::tie(other.interface_index, other.family, other.address);
}

void InterfaceTable::clear() {
    interfaces_.clear();
    addresses_.clear();
}

NetlinkBatchResult InterfaceTable::apply_netlink_datagram(
    const void* data, std::size_t size, std::uint32_t expected_sequence) {
    auto parsed = parse_datagram(data, size, expected_sequence);
    if(!parsed.result.ok) return parsed.result;

    for(const auto& event : parsed.events) {
        switch(event.kind) {
            case EventKind::new_link: {
                const auto found = interfaces_.find(event.interface.index);
                if(found == interfaces_.end() || !same_interface(found->second, event.interface)) {
                    interfaces_[event.interface.index] = event.interface;
                    parsed.result.changed = true;
                }
                break;
            }
            case EventKind::delete_link: {
                parsed.result.changed = interfaces_.erase(event.interface.index) != 0 ||
                                        parsed.result.changed;
                for(auto it = addresses_.begin(); it != addresses_.end();) {
                    if(it->first.interface_index == event.interface.index) {
                        it = addresses_.erase(it);
                        parsed.result.changed = true;
                    } else {
                        ++it;
                    }
                }
                break;
            }
            case EventKind::new_address: {
                const AddressKey key{event.address.interface_index,
                                     event.address.family,
                                     event.address.address};
                const auto found = addresses_.find(key);
                if(found == addresses_.end() ||
                   !same_address(found->second.value, event.address) ||
                   found->second.label != event.address_label) {
                    addresses_[key] = AddressRecord{event.address, event.address_label};
                    parsed.result.changed = true;
                }
                break;
            }
            case EventKind::delete_address: {
                const AddressKey key{event.address.interface_index,
                                     event.address.family,
                                     event.address.address};
                parsed.result.changed = addresses_.erase(key) != 0 || parsed.result.changed;
                break;
            }
        }
    }
    return parsed.result;
}

std::shared_ptr<const InterfaceSnapshot> InterfaceTable::snapshot(
    std::uint64_t generation, bool valid) const {
    auto output = std::make_shared<InterfaceSnapshot>();
    output->generation = generation;
    output->valid = valid;
    output->interfaces.reserve(interfaces_.size());
    output->addresses.reserve(addresses_.size());
    for(const auto& [index, interface] : interfaces_) output->interfaces.push_back(interface);
    for(const auto& [key, record] : addresses_) {
        auto address = record.value;
        const auto interface = interfaces_.find(key.interface_index);
        address.interface_name = interface != interfaces_.end()
            ? interface->second.name : record.label;
        output->addresses.push_back(std::move(address));
    }
    return output;
}

} // namespace detail

InterfaceMonitor::InterfaceMonitor() {
    snapshot_ = table_.snapshot(0, false);
}

InterfaceMonitor::~InterfaceMonitor() {
    stop();
}

InterfaceMonitor& InterfaceMonitor::instance() {
    static InterfaceMonitor monitor;
    return monitor;
}

bool InterfaceMonitor::start() {
    std::unique_lock lock(lifecycle_mutex_);
    if(worker_.joinable()) {
        return running_.load(std::memory_order_acquire) &&
               std::atomic_load_explicit(&snapshot_, std::memory_order_acquire)->valid;
    }

    stop_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if(stop_fd_ < 0) {
        std::lock_guard error_lock(error_mutex_);
        last_error_ = std::string("cannot create interface monitor eventfd: ") +
                      std::strerror(errno);
        return false;
    }

    stop_requested_.store(false, std::memory_order_release);
    initial_complete_ = false;
    initial_success_ = false;
    worker_ = std::thread(&InterfaceMonitor::run, this);
    initial_condition_.wait(lock, [this] { return initial_complete_; });
    return initial_success_;
}

void InterfaceMonitor::stop() noexcept {
    std::thread worker;
    int stop_fd = -1;
    {
        std::lock_guard lock(lifecycle_mutex_);
        if(!worker_.joinable()) return;
        stop_requested_.store(true, std::memory_order_release);
        stop_fd = stop_fd_;
        worker = std::move(worker_);
    }

    if(stop_fd >= 0) {
        eventfd_t signal = 1;
        (void)::eventfd_write(stop_fd, signal);
    }
    if(worker.joinable()) worker.join();

    {
        std::lock_guard lock(lifecycle_mutex_);
        if(stop_fd_ >= 0) ::close(stop_fd_);
        stop_fd_ = -1;
    }
}

bool InterfaceMonitor::running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

std::shared_ptr<const InterfaceSnapshot> InterfaceMonitor::snapshot() const noexcept {
    return std::atomic_load_explicit(&snapshot_, std::memory_order_acquire);
}

std::string InterfaceMonitor::last_error() const {
    std::lock_guard lock(error_mutex_);
    return last_error_;
}

void InterfaceMonitor::publish(bool valid) {
    auto next = table_.snapshot(++generation_, valid);
    std::atomic_store_explicit(&snapshot_, std::move(next), std::memory_order_release);
}

void InterfaceMonitor::publish_invalid(const std::string& error) {
    {
        std::lock_guard lock(error_mutex_);
        last_error_ = error;
    }
    publish(false);
}

void InterfaceMonitor::signal_initial_result(bool success) {
    std::lock_guard lock(lifecycle_mutex_);
    if(initial_complete_) return;
    initial_success_ = success;
    initial_complete_ = true;
    initial_condition_.notify_all();
}

bool InterfaceMonitor::stop_requested() const noexcept {
    return stop_requested_.load(std::memory_order_acquire);
}

void InterfaceMonitor::run() noexcept {
    (void)::pthread_setname_np(::pthread_self(), "sxy_ifmon");
    running_.store(true, std::memory_order_release);
    bool initial_reported = false;
    std::uint32_t sequence = 0;

    while(!stop_requested()) {
        std::string error;
        const int netlink_fd = open_route_socket(error);
        if(netlink_fd < 0) {
            publish_invalid(error);
            if(!initial_reported) {
                signal_initial_result(false);
                initial_reported = true;
            }
            if(wait_for_retry_or_stop(stop_fd_, 1000)) break;
            continue;
        }

        detail::InterfaceTable fresh;
        const auto sync = synchronize_table(netlink_fd, stop_fd_, fresh, sequence, error);
        if(sync == SyncStatus::stopped) {
            ::close(netlink_fd);
            break;
        }
        if(sync == SyncStatus::failed) {
            ::close(netlink_fd);
            publish_invalid(error);
            if(!initial_reported) {
                signal_initial_result(false);
                initial_reported = true;
            }
            if(wait_for_retry_or_stop(stop_fd_, 1000)) break;
            continue;
        }

        table_ = std::move(fresh);
        {
            std::lock_guard lock(error_mutex_);
            last_error_.clear();
        }
        publish(true);
        if(!initial_reported) {
            signal_initial_result(true);
            initial_reported = true;
        }

        bool resynchronize = false;
        while(!stop_requested() && !resynchronize) {
            auto received = receive_datagram(netlink_fd, stop_fd_, table_, 0, -1);
            switch(received.status) {
                case ReceiveStatus::stopped:
                    break;
                case ReceiveStatus::failed:
                    error = std::move(received.error);
                    publish_invalid(error);
                    resynchronize = true;
                    break;
                case ReceiveStatus::received:
                    if(received.batch.changed) publish(true);
                    break;
                case ReceiveStatus::would_block:
                    break;
            }
            if(received.status == ReceiveStatus::stopped) break;
        }
        ::close(netlink_fd);
        if(stop_requested()) break;
        if(resynchronize && !wait_for_retry_or_stop(stop_fd_, 100)) continue;
    }

    if(!initial_reported) signal_initial_result(false);
    running_.store(false, std::memory_order_release);
}

} // namespace sx::net
