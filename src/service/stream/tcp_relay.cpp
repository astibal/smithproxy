#include <service/stream/tcp_relay.hpp>

#include <service/cli/cli_broker.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <memory>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <fcntl.h>

namespace {

std::atomic<bool> relay_stop{false};

void request_stop(int) { relay_stop.store(true, std::memory_order_relaxed); }

int connect_upstream(const sx::comm::stream::TcpRelayConfig& config) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* addresses = nullptr;
    const auto service = std::to_string(config.destination_port);
    const int lookup = ::getaddrinfo(config.destination_host.c_str(), service.c_str(),
                                     &hints, &addresses);
    if(lookup != 0) { errno = EHOSTUNREACH; return -1; }
    int saved = ECONNREFUSED;
    int connected = -1;
    for(auto* address = addresses; address != nullptr; address = address->ai_next) {
        const int fd = ::socket(address->ai_family,
                                address->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                address->ai_protocol);
        if(fd < 0) { saved = errno; continue; }
        if(!config.bind_interface.empty()
           && ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, config.bind_interface.c_str(),
                           static_cast<socklen_t>(config.bind_interface.size() + 1)) != 0) {
            saved = errno; ::close(fd); continue;
        }
        if(::connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
            connected = fd; break;
        }
        if(errno != EINPROGRESS) { saved = errno; ::close(fd); continue; }
        pollfd descriptor{fd, POLLOUT, 0};
        int ready;
        do { ready = ::poll(&descriptor, 1, config.connect_timeout_ms); }
        while(ready < 0 && errno == EINTR);
        if(ready > 0 && (descriptor.revents & POLLOUT)) {
            int error = 0;
            socklen_t size = sizeof(error);
            if(::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0) {
                connected = fd; break;
            }
            saved = error == 0 ? ECONNREFUSED : error;
        } else {
            saved = ready == 0 ? ETIMEDOUT : errno;
        }
        ::close(fd);
    }
    ::freeaddrinfo(addresses);
    if(connected < 0) errno = saved;
    return connected;
}

} // namespace

namespace sx::comm::stream {

class TcpRelaySharedStats {
public:
    std::atomic<std::uint64_t> accepted{0};
    std::atomic<std::uint64_t> rejected{0};
    std::atomic<std::uint64_t> upstream_connect_errors{0};
    std::atomic<std::uint64_t> active{0};
    std::atomic<std::uint64_t> peak_active{0};
    std::atomic<std::uint64_t> completed{0};
    std::atomic<std::uint64_t> relay_errors{0};
    std::atomic<std::uint64_t> bytes_to_upstream{0};
    std::atomic<std::uint64_t> bytes_from_upstream{0};
};

TcpRelaySharedStats* create_tcp_relay_shared_stats() {
    void* memory = ::mmap(nullptr, sizeof(TcpRelaySharedStats), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(memory == MAP_FAILED) return nullptr;
    return new(memory) TcpRelaySharedStats();
}

void destroy_tcp_relay_shared_stats(TcpRelaySharedStats* stats) {
    if(!stats) return;
    stats->~TcpRelaySharedStats();
    ::munmap(stats, sizeof(TcpRelaySharedStats));
}

TcpRelayStats tcp_relay_snapshot(const TcpRelaySharedStats* stats) noexcept {
    if(!stats) return {};
    return {stats->accepted.load(), stats->rejected.load(),
            stats->upstream_connect_errors.load(), stats->active.load(),
            stats->peak_active.load(), stats->completed.load(),
            stats->relay_errors.load(), stats->bytes_to_upstream.load(),
            stats->bytes_from_upstream.load()};
}

int TcpRelayServer::run() {
    relay_stop.store(false, std::memory_order_relaxed);
    struct sigaction action{};
    action.sa_handler = request_stop;
    ::sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, nullptr);
    ::sigaction(SIGTERM, &action, nullptr);
    return run_until(relay_stop);
}

int TcpRelayServer::run_until(std::atomic<bool>& stop) {
    if(config_.comm_path.empty() || config_.destination_host.empty()
       || config_.destination_port == 0 || config_.max_active_sessions == 0
       || config_.connect_timeout_ms < 1 || config_.idle_timeout_ms < 1) {
        errno = EINVAL;
        return -1;
    }
    const int listener = create_unix_listener(config_.comm_path);
    if(listener < 0) return -1;
    struct stat owned_socket{};
    const bool filesystem_socket = config_.comm_path.front() != '@';
    const bool have_owned_socket = filesystem_socket
        && ::lstat(config_.comm_path.c_str(), &owned_socket) == 0;
    const auto unlink_owned_socket = [&] {
        if(!have_owned_socket) return;
        struct stat current{};
        if(::lstat(config_.comm_path.c_str(), &current) == 0
           && current.st_dev == owned_socket.st_dev && current.st_ino == owned_socket.st_ino)
            ::unlink(config_.comm_path.c_str());
    };
    struct Session {
        std::thread worker;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<Session> sessions;
    try { sessions.reserve(config_.max_active_sessions); }
    catch(...) {
        ::close(listener);
        unlink_owned_socket();
        errno = ENOMEM;
        return -1;
    }
    std::atomic<std::uint64_t> active_sessions{0};
    int result = 0;
    while(!stop.load(std::memory_order_relaxed)) {
        for(auto it = sessions.begin(); it != sessions.end();) {
            if(it->done->load(std::memory_order_acquire)) {
                if(it->worker.joinable()) it->worker.join();
                it = sessions.erase(it);
            } else ++it;
        }
        pollfd descriptor{listener, POLLIN, 0};
        int ready;
        do { ready = ::poll(&descriptor, 1, 250); } while(ready < 0 && errno == EINTR);
        if(ready < 0) {
            result = -1;
            stop.store(true, std::memory_order_relaxed);
            break;
        }
        if(ready == 0 || !(descriptor.revents & POLLIN)) continue;
        const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if(client < 0) continue;
        if(stats_) stats_->accepted.fetch_add(1);
        if(active_sessions.load(std::memory_order_relaxed) >= config_.max_active_sessions) {
            if(stats_) stats_->rejected.fetch_add(1);
            ::close(client);
            continue;
        }
        active_sessions.fetch_add(1, std::memory_order_relaxed);
        if(stats_) {
            const auto active = stats_->active.fetch_add(1) + 1;
            auto peak = stats_->peak_active.load();
            while(active > peak && !stats_->peak_active.compare_exchange_weak(peak, active)) {}
        }
        try {
            auto done = std::make_shared<std::atomic<bool>>(false);
            Session session;
            session.done = done;
            session.worker = std::thread([client, config = config_, stats = stats_, done,
                                          &active_sessions, &stop] {
                const int upstream = connect_upstream(config);
                int relay_result = 0;
                if(upstream >= 0) {
                    relay_result = DuplexRelay{}.run(
                        client, upstream, stop, nullptr,
                        stats ? &stats->bytes_to_upstream : nullptr,
                        stats ? &stats->bytes_from_upstream : nullptr,
                        config.idle_timeout_ms);
                } else if(stats) stats->upstream_connect_errors.fetch_add(1);
                if(upstream >= 0) ::close(upstream);
                ::close(client);
                if(stats) {
                    if(relay_result != 0) stats->relay_errors.fetch_add(1);
                    stats->active.fetch_sub(1);
                    stats->completed.fetch_add(1);
                }
                active_sessions.fetch_sub(1, std::memory_order_relaxed);
                done->store(true, std::memory_order_release);
            });
            sessions.emplace_back(std::move(session));
        } catch(...) {
            ::close(client);
            active_sessions.fetch_sub(1, std::memory_order_relaxed);
            if(stats_) { stats_->active.fetch_sub(1); stats_->rejected.fetch_add(1); }
        }
    }
    ::close(listener);
    unlink_owned_socket();
    for(auto& session: sessions) if(session.worker.joinable()) session.worker.join();
    return result;
}

} // namespace sx::comm::stream
