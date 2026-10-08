#include <service/cli/cli_broker.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <mutex>
#include <memory>
#include <poll.h>
#include <signal.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <arpa/inet.h>

namespace {

constexpr std::array<char, 8> cli_handshake{'S', 'C', 'C', 'L', 1, 0, 0, 0};
std::mutex state_mutex;
int core_listener = -1;
pid_t broker_pid = -1;
std::string owned_path;
std::atomic<bool> broker_stop{false};
std::atomic<bool> broker_stopping{false};
std::atomic<int> broker_wait_status{0};
std::thread broker_monitor;
std::function<void()> internal_failure_handler;
sx::comm::stream::SharedStats* shared_stats = nullptr;

int unix_address(const std::string& path, sockaddr_un& address, socklen_t& length) {
    if(path.empty()) { errno = EINVAL; return -1; }
    address = {};
    address.sun_family = AF_UNIX;
    if(path.front() == '@') {
        if(path.size() > sizeof(address.sun_path)) { errno = ENAMETOOLONG; return -1; }
        std::memcpy(address.sun_path + 1, path.data() + 1, path.size() - 1);
        length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size());
    } else {
        if(path.size() >= sizeof(address.sun_path)) { errno = ENAMETOOLONG; return -1; }
        std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
        length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);
    }
    return 0;
}

int make_unix_listener(const std::string& path) {
    sockaddr_un address{};
    socklen_t length = 0;
    if(unix_address(path, address, length) != 0) return -1;
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    if(::bind(fd, reinterpret_cast<sockaddr*>(&address), length) != 0) {
        const int saved = errno; ::close(fd); errno = saved; return -1;
    }
    if(path.front() != '@' && ::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        const int saved = errno; ::close(fd); ::unlink(path.c_str()); errno = saved; return -1;
    }
    if(::listen(fd, 50) != 0) {
        const int saved = errno; ::close(fd);
        if(path.front() != '@') ::unlink(path.c_str());
        errno = saved; return -1;
    }
    return fd;
}

int connect_unix(const std::string& path) {
    sockaddr_un address{};
    socklen_t length = 0;
    if(unix_address(path, address, length) != 0) return -1;
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    if(::connect(fd, reinterpret_cast<sockaddr*>(&address), length) != 0) {
        const int saved = errno; ::close(fd); errno = saved; return -1;
    }
    return fd;
}

int write_all(int fd, const char* data, std::size_t size) {
    std::size_t offset = 0;
    while(offset < size) {
        const auto written = ::send(fd, data + offset, size - offset, MSG_NOSIGNAL);
        if(written > 0) { offset += static_cast<std::size_t>(written); continue; }
        if(written < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

int make_tcp_listener(const sx::comm::stream::BrokerConfig& config) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config.listen_port);
    if(::inet_pton(AF_INET, config.listen_address.c_str(), &address.sin_addr) != 1) {
        errno = EINVAL; return -1;
    }
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    int reuse = 1;
    if(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        const int saved = errno; ::close(fd); errno = saved; return -1;
    }
    if(!config.bind_interface.empty()
       && ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, config.bind_interface.c_str(),
                       static_cast<socklen_t>(config.bind_interface.size())) != 0) {
        const int saved = errno; ::close(fd); errno = saved; return -1;
    }
    if(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0
       || ::listen(fd, 50) != 0) {
        const int saved = errno; ::close(fd); errno = saved; return -1;
    }
    return fd;
}

void request_stop(int) { broker_stop.store(true, std::memory_order_relaxed); }

} // namespace

namespace sx::comm::stream {

class SharedStats {
public:
    std::atomic<std::uint64_t> accepted{0};
    std::atomic<std::uint64_t> rejected{0};
    std::atomic<std::uint64_t> core_connect_errors{0};
    std::atomic<std::uint64_t> active{0};
    std::atomic<std::uint64_t> peak_active{0};
    std::atomic<std::uint64_t> completed{0};
    std::atomic<std::uint64_t> relay_errors{0};
    std::atomic<std::uint64_t> bytes_to_core{0};
    std::atomic<std::uint64_t> bytes_from_core{0};
};

SharedStats* create_shared_stats() {
    void* memory = ::mmap(nullptr, sizeof(SharedStats), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(memory == MAP_FAILED) return nullptr;
    return new(memory) SharedStats();
}

void destroy_shared_stats(SharedStats* stats) {
    if(!stats) return;
    stats->~SharedStats();
    ::munmap(stats, sizeof(SharedStats));
}

Stats snapshot(const SharedStats* stats) noexcept {
    if(!stats) return {};
    return {stats->accepted.load(), stats->rejected.load(),
            stats->core_connect_errors.load(), stats->active.load(),
            stats->peak_active.load(), stats->completed.load(),
            stats->relay_errors.load(), stats->bytes_to_core.load(),
            stats->bytes_from_core.load()};
}

int create_unix_listener(const std::string& path) { return make_unix_listener(path); }

int DuplexRelay::run(int left, int right, const std::atomic<bool>& stop,
                     SharedStats* stats,
                     std::atomic<std::uint64_t>* bytes_left_to_right,
                     std::atomic<std::uint64_t>* bytes_right_to_left,
                     int idle_timeout_ms) const {
    struct Direction { int source; int destination; std::array<char, 65536> data{}; std::size_t size = 0; std::size_t offset = 0; bool eof = false; };
    Direction directions[2]{{left, right}, {right, left}};
    auto last_activity = std::chrono::steady_clock::now();
    for(int fd: {left, right}) {
        const int flags = ::fcntl(fd, F_GETFL);
        if(flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    }
    while(!stop.load(std::memory_order_relaxed)) {
        if(idle_timeout_ms > 0
           && std::chrono::steady_clock::now() - last_activity
               >= std::chrono::milliseconds(idle_timeout_ms)) {
            errno = ETIMEDOUT;
            return -1;
        }
        if(directions[0].eof && directions[1].eof
           && directions[0].size == directions[0].offset
           && directions[1].size == directions[1].offset) return 0;
        pollfd descriptors[2]{{left, 0, 0}, {right, 0, 0}};
        for(unsigned i = 0; i < 2; ++i) {
            auto& direction = directions[i];
            if(!direction.eof && direction.size == direction.offset) descriptors[i].events |= POLLIN;
            if(direction.size > direction.offset) descriptors[1U - i].events |= POLLOUT;
        }
        int ready;
        do { ready = ::poll(descriptors, 2, 250); } while(ready < 0 && errno == EINTR);
        if(ready < 0) return -1;
        for(unsigned i = 0; i < 2; ++i) {
            auto& direction = directions[i];
            if((descriptors[i].revents & (POLLIN | POLLHUP)) && !direction.eof
               && direction.size == direction.offset) {
                const auto count = ::read(direction.source, direction.data.data(), direction.data.size());
                if(count > 0) {
                    direction.size = static_cast<std::size_t>(count);
                    direction.offset = 0;
                    last_activity = std::chrono::steady_clock::now();
                }
                else if(count == 0) { direction.eof = true; ::shutdown(direction.destination, SHUT_WR); }
                else if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
            }
            if((descriptors[1U - i].revents & POLLOUT) && direction.size > direction.offset) {
                const auto count = ::send(direction.destination, direction.data.data() + direction.offset,
                                          direction.size - direction.offset, MSG_NOSIGNAL);
                if(count > 0) {
                    last_activity = std::chrono::steady_clock::now();
                    direction.offset += static_cast<std::size_t>(count);
                    if(stats) {
                        auto& counter = i == 0 ? stats->bytes_to_core : stats->bytes_from_core;
                        counter.fetch_add(static_cast<std::uint64_t>(count));
                    }
                    auto* direct_counter = i == 0 ? bytes_left_to_right : bytes_right_to_left;
                    if(direct_counter) direct_counter->fetch_add(static_cast<std::uint64_t>(count));
                }
                else if(count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
            }
        }
    }
    return 0;
}

int BrokerServer::run() {
    broker_stop.store(false, std::memory_order_relaxed);
    struct sigaction action{};
    action.sa_handler = request_stop;
    ::sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, nullptr);
    ::sigaction(SIGTERM, &action, nullptr);
    const int listener = make_tcp_listener(config_);
    if(listener < 0) return -1;
    struct Session {
        std::thread worker;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<Session> sessions;
    try {
        sessions.reserve(config_.max_active_sessions);
    } catch(...) {
        ::close(listener);
        errno = ENOMEM;
        return -1;
    }
    std::atomic<std::uint64_t> active_sessions{0};
    while(!broker_stop.load(std::memory_order_relaxed)) {
        for(auto it = sessions.begin(); it != sessions.end();) {
            if(it->done->load(std::memory_order_acquire)) {
                if(it->worker.joinable()) it->worker.join();
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
        pollfd descriptor{listener, POLLIN, 0};
        int ready;
        do { ready = ::poll(&descriptor, 1, 250); } while(ready < 0 && errno == EINTR);
        if(ready < 0) { ::close(listener); return -1; }
        if(ready == 0 || !(descriptor.revents & POLLIN)) continue;
        sockaddr_in peer{};
        socklen_t peer_size = sizeof(peer);
        const int client = ::accept4(listener, reinterpret_cast<sockaddr*>(&peer), &peer_size,
                                     SOCK_CLOEXEC);
        if(client < 0) continue;
        if(stats_) stats_->accepted.fetch_add(1);
        std::array<char, INET_ADDRSTRLEN> peer_text{};
        const char* converted = ::inet_ntop(AF_INET, &peer.sin_addr,
                                            peer_text.data(), peer_text.size());
        const std::string peer_ip = converted ? converted : std::string{};
        const bool allowed = std::any_of(config_.allowed_ips.begin(), config_.allowed_ips.end(),
            [&peer_ip](const std::string& value) {
                return value == "*" || value == "all" || value == peer_ip;
            });
        if(!allowed) {
            if(stats_) stats_->rejected.fetch_add(1);
            ::close(client); continue;
        }
        if(active_sessions.load(std::memory_order_relaxed) >= config_.max_active_sessions) {
            if(stats_) stats_->rejected.fetch_add(1);
            ::close(client); continue;
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
            session.worker = std::thread([client, path = config_.comm_path,
                                          preamble = config_.preamble, stats = stats_, done,
                                          &active_sessions] {
                const int core = connect_unix(path);
                int relay_result = 0;
                if(core >= 0
                   && (preamble.empty()
                       || write_all(core, preamble.data(), preamble.size()) == 0))
                    relay_result = DuplexRelay{}.run(client, core, broker_stop, stats);
                else if(stats) stats->core_connect_errors.fetch_add(1);
                if(core >= 0) ::close(core);
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
            if(stats_) {
                stats_->active.fetch_sub(1);
                stats_->rejected.fetch_add(1);
            }
        }
    }
    ::close(listener);
    for(auto& session: sessions) if(session.worker.joinable()) session.worker.join();
    return 0;
}

} // namespace sx::comm::stream

namespace sx::comm::cli {

std::string handshake() { return {cli_handshake.data(), cli_handshake.size()}; }

int start_internal_broker(std::uint16_t port) {
    std::lock_guard lock(state_mutex);
    if(core_listener >= 0 || broker_pid > 0) { errno = EALREADY; return -1; }
    shared_stats = sx::comm::stream::create_shared_stats();
    if(!shared_stats) return -1;
    const std::string path = "@smithproxy-cli-" + std::to_string(::getpid());
    core_listener = sx::comm::stream::create_unix_listener(path);
    if(core_listener < 0) { sx::comm::stream::destroy_shared_stats(shared_stats); shared_stats = nullptr; return -1; }
    const pid_t child = ::fork();
    if(child < 0) {
        const int saved = errno;
        ::close(core_listener); core_listener = -1;
        sx::comm::stream::destroy_shared_stats(shared_stats); shared_stats = nullptr;
        errno = saved; return -1;
    }
    if(child == 0) {
        ::close(core_listener);
        CliBrokerServer server({"127.0.0.1", port, path, handshake(), {"*"}, {}, 256}, shared_stats);
        ::_exit(server.run() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    broker_pid = child;
    broker_stopping.store(false, std::memory_order_relaxed);
    broker_monitor = std::thread([child] {
        int status = 0;
        pid_t result;
        do { result = ::waitpid(child, &status, 0); } while(result < 0 && errno == EINTR);
        broker_wait_status.store(result == child ? status : -1, std::memory_order_relaxed);
        std::function<void()> handler;
        {
            std::lock_guard lock(state_mutex);
            if(!broker_stopping.load(std::memory_order_relaxed)) handler = internal_failure_handler;
        }
        if(handler) handler();
    });
    return 0;
}

int prepare_external_ingress(const std::string& path) {
    std::lock_guard lock(state_mutex);
    if(core_listener >= 0 || broker_pid > 0) { errno = EALREADY; return -1; }
    core_listener = sx::comm::stream::create_unix_listener(path);
    if(core_listener < 0) return -1;
    owned_path = path;
    return 0;
}

int ingress_fd() {
    std::lock_guard lock(state_mutex);
    if(core_listener < 0) { errno = ENOTCONN; return -1; }
    return ::fcntl(core_listener, F_DUPFD_CLOEXEC, 0);
}

bool receive_handshake(int fd, int timeout_ms) {
    std::array<char, cli_handshake.size()> received{};
    std::size_t offset = 0;
    while(offset < received.size()) {
        pollfd descriptor{fd, POLLIN, 0};
        int ready;
        do { ready = ::poll(&descriptor, 1, timeout_ms); } while(ready < 0 && errno == EINTR);
        if(ready <= 0 || !(descriptor.revents & POLLIN)) return false;
        const auto count = ::read(fd, received.data() + offset, received.size() - offset);
        if(count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return received == cli_handshake;
}

int stop_broker() {
    pid_t child = -1;
    {
        std::lock_guard lock(state_mutex);
        broker_stopping.store(true, std::memory_order_relaxed);
        if(core_listener >= 0) { ::close(core_listener); core_listener = -1; }
        if(!owned_path.empty()) { ::unlink(owned_path.c_str()); owned_path.clear(); }
        child = broker_pid;
    }
    if(child > 0) ::kill(child, SIGTERM);
    if(broker_monitor.joinable()) broker_monitor.join();
    const int status = broker_wait_status.load(std::memory_order_relaxed);
    {
        std::lock_guard lock(state_mutex);
        broker_pid = -1;
        sx::comm::stream::destroy_shared_stats(shared_stats);
        shared_stats = nullptr;
    }
    if(child <= 0) return 0;
    return status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS ? 0 : -1;
}

pid_t internal_broker_pid() noexcept { std::lock_guard lock(state_mutex); return broker_pid; }

void set_internal_failure_handler(std::function<void()> handler) {
    std::lock_guard lock(state_mutex);
    internal_failure_handler = std::move(handler);
}

sx::comm::stream::Stats stats() noexcept {
    std::lock_guard lock(state_mutex);
    return sx::comm::stream::snapshot(shared_stats);
}

bool uses_external_broker() noexcept { std::lock_guard lock(state_mutex); return !owned_path.empty(); }
std::string external_path() { std::lock_guard lock(state_mutex); return owned_path; }

} // namespace sx::comm::cli
