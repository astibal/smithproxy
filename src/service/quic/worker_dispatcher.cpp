#include "proxy/quic/error_stats.hpp"
#include "service/quic/worker_dispatcher.hpp"

#if SMITHPROXY_OPENSSL_QUIC
#include "proxy/quic/socket_io_detail.hpp"
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <array>
#include <algorithm>
#include <stdexcept>
#include <system_error>
#include <sys/eventfd.h>
#include <unistd.h>

namespace sx::quic {

struct worker_dispatcher::inbox {
    // The receiver cannot let a slow owner consume unbounded memory. Dropping
    // on overload leaves QUIC recovery with the original owner, never a sibling.
    std::mutex lock;
    std::deque<datagram_packet> packets;
    std::size_t bytes = 0;
    socle::raw::var<int> wake {::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC), close_descriptor};
    bool retired = false;
    std::atomic_uint64_t dropped {0};
};

worker_dispatcher::worker_dispatcher(std::size_t workers, std::size_t max_packets,
                                     std::size_t max_bytes)
    : max_packets_(max_packets), max_bytes_(max_bytes) {
    if (!max_packets_ || !max_bytes_) {
        ++stats.errors.dispatcher_create_quic_inbox_capacities_must_be_positive;
        throw std::invalid_argument("QUIC inbox capacities must be positive");
    }
    if (workers == 0) {
        ++stats.errors.dispatcher_create_quic_receiver_needs_a_worker;
        throw std::invalid_argument("QUIC receiver needs a worker");
    }
    for (std::size_t i = 0; i < workers; ++i) {
        auto queue = std::make_unique<inbox>();
        if (queue->wake.value < 0) {
            ++stats.errors.dispatcher_create_quic_inbox_eventfd;
            throw std::system_error(errno, std::generic_category(), "QUIC inbox eventfd");
        }
        inboxes_.push_back(std::move(queue));
    }
    stop_fd_.value = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (stop_fd_.value < 0) {
        ++stats.errors.dispatcher_create_quic_receiver_eventfd;
        throw std::system_error(errno, std::generic_category(), "QUIC receiver eventfd");
    }
}

worker_dispatcher::~worker_dispatcher() {
    stop();
}

bool worker_dispatcher::attach_socket(int fd) {
    // Setup is serial, before workers launch. Keep the ingress alive even when
    // the first service is destroyed before its siblings during shutdown.
    if (socket_fd_.value >= 0) return true;
    socket_fd_.value = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
    return socket_fd_.value >= 0;
}

std::size_t worker_dispatcher::owner(datagram_endpoint const& destination) const {
    unsigned char const* bytes = nullptr;
    std::size_t length = 0;
    if (destination.valid() && destination.address.ss_family == AF_INET) {
        bytes = reinterpret_cast<unsigned char const*>(
            &reinterpret_cast<sockaddr_in const*>(&destination.address)->sin_addr);
        length = sizeof(in_addr);
    } else if (destination.valid() && destination.address.ss_family == AF_INET6) {
        bytes = reinterpret_cast<unsigned char const*>(
            &reinterpret_cast<sockaddr_in6 const*>(&destination.address)->sin6_addr);
        length = sizeof(in6_addr);
    }
    std::uint64_t hash = 14695981039346656037ULL;
    for (std::size_t i = 0; i < length; ++i) hash = (hash ^ bytes[i]) * 1099511628211ULL;
    return hash % inboxes_.size();
}

bool worker_dispatcher::start() {
    std::lock_guard lock(lifecycle_lock_);
    if (thread_.joinable()) return error() == 0;
    if (socket_fd_.value < 0 || stopping_) return false;
    try {
        thread_ = std::thread([this] { run(); });
    } catch (std::system_error const& error) {
        ++stats.errors.dispatcher_start_exception;
        ++stats.errors.dispatcher_start_failure;
        fail(error.code().value());
        return false;
    }
    return true;
}

void worker_dispatcher::stop() {
    std::lock_guard lock(lifecycle_lock_);
    stopping_ = true;
    (void)::eventfd_write(stop_fd_.value, 1);
    if (thread_.joinable()) thread_.join();
}

void worker_dispatcher::retire(std::size_t worker) {
    auto& queue = *inboxes_.at(worker);
    {
        std::lock_guard lock(queue.lock);
        if (queue.retired) return;
        queue.retired = true;
        queue.packets.clear();
        queue.bytes = 0;
        eventfd_t ignored;
        (void)::eventfd_read(queue.wake.value, &ignored);
    }
    if (++retired_ == inboxes_.size()) stop();
}

int worker_dispatcher::wake_fd(std::size_t worker) const {
    return inboxes_.at(worker)->wake.value;
}

bool worker_dispatcher::pop(std::size_t worker, datagram_packet& packet) {
    return pop_batch(worker, &packet, 1) != 0;
}

std::size_t worker_dispatcher::pop_batch(
        std::size_t worker, datagram_packet* packets, std::size_t capacity) {
    if (!capacity) return 0;
    auto& queue = *inboxes_.at(worker);
    std::lock_guard lock(queue.lock);
    auto count = std::min({capacity, datagram_batch_limit, queue.packets.size()});
    for (std::size_t i = 0; i < count; ++i) {
        queue.bytes -= queue.packets.front().data.size();
        packets[i] = std::move(queue.packets.front());
        queue.packets.pop_front();
    }
    // Clear under the same lock as enqueue's empty-to-nonempty transition:
    // a producer arriving afterwards must publish a fresh wakeup.
    if (count && queue.packets.empty()) {
        eventfd_t ignored;
        (void)::eventfd_read(queue.wake.value, &ignored);
    }
    return count;
}

bool worker_dispatcher::enqueue(datagram_packet packet) {
    return enqueue_batch(&packet, 1) != 0;
}

std::size_t worker_dispatcher::enqueue_batch(datagram_packet* packets, std::size_t count) {
    if (count > datagram_batch_limit) {
        ++stats.errors.dispatcher_enqueue_batch_quic_inbox_batch_too_large;
        throw std::invalid_argument("QUIC inbox batch too large");
    }
    // A small fixed routing array avoids per-batch maps and allocations. Mark
    // handled slots with size(), which cannot name a worker. Relative order
    // within each owner's queue is the same as the receive order.
    std::array<std::size_t, datagram_batch_limit> owners;
    for (std::size_t i = 0; i < count; ++i) owners[i] = owner(packets[i].local);
    std::size_t accepted = 0;
    for (std::size_t first = 0; first < count; ++first) {
        auto worker = owners[first];
        if (worker == inboxes_.size()) continue;
        auto& queue = *inboxes_[worker];
        std::lock_guard lock(queue.lock);
        bool const was_empty = queue.packets.empty();
        for (std::size_t i = first; i < count; ++i) {
            if (owners[i] != worker) continue;
            owners[i] = inboxes_.size();
            auto& packet = packets[i];
            if (queue.retired || queue.packets.size() >= max_packets_
                || packet.data.size() > max_bytes_ - queue.bytes) {
                ++queue.dropped;
                continue;
            }
            queue.bytes += packet.data.size();
            queue.packets.push_back(std::move(packet));
            ++accepted;
        }
        if (was_empty && !queue.packets.empty()) (void)::eventfd_write(queue.wake.value, 1);
    }
    return accepted;
}

std::uint64_t worker_dispatcher::dropped(std::size_t worker) const {
    return inboxes_.at(worker)->dropped.load();
}

void worker_dispatcher::fail(int error) {
    error_ = error;
    for (auto const& queue : inboxes_) (void)::eventfd_write(queue->wake.value, 1);
}

void worker_dispatcher::run() {
    pthread_setname_np(pthread_self(), "sxy_quic_rx");
    datagram_receiver receiver;
    while (!stopping_) {
        pollfd descriptors[] {{socket_fd_.value, POLLIN, 0}, {stop_fd_.value, POLLIN, 0}};
        auto const ready = ::poll(descriptors, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            ++stats.errors.dispatcher_run_poll_error;
            fail(errno);
            break;
        }
        if (stopping_ || descriptors[1].revents) break;
        if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            ++stats.errors.dispatcher_run_socket_error;
            fail(EIO);
            break;
        }
        for (std::size_t i = 0; i < 64 && !stopping_;) {
            std::array<datagram_packet, datagram_receiver::capacity> packets;
            std::size_t valid = 0;
            auto count = receiver.receive(socket_fd_.value, [&](datagram_packet&& packet) {
                if (packet.peer.valid() && packet.local.valid()) packets[valid++] = std::move(packet);
            });
            enqueue_batch(packets.data(), valid);
            if (count < 0) {
                if (detail::datagram_receive_would_block(errno)) break;
                ++stats.errors.dispatcher_run_receive_failure;
                fail(errno);
                return;
            }
            if (!count) break;
            i += count;
            if (static_cast<size_t>(count) < datagram_receiver::capacity) break;
        }
    }
}

} // namespace sx::quic
#endif
