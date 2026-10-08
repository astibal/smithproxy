#include <service/gre_broker.hpp>

#include <service/comm.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

constexpr std::uint8_t gre_frame_opcode = 1;
constexpr std::uint8_t gre_stats_opcode = 2;
constexpr std::size_t broker_stats_size = 3 * sizeof(std::uint64_t);

struct SharedStats {
    std::atomic<std::uint64_t> submitted{0};
    std::atomic<std::uint64_t> dropped{0};
    std::atomic<std::uint64_t> received{0};
    std::atomic<std::uint64_t> exported{0};
    std::atomic<std::uint64_t> errors{0};
    std::atomic<std::uint64_t> reconnects{0};
    std::atomic<bool> connected{false};
};

std::mutex state_mutex;
std::shared_ptr<SharedStats> shared_stats;
std::shared_ptr<socle::traflog::GreTransport> installed_transport;
pid_t broker_pid = -1;
std::thread broker_monitor;
std::atomic<bool> broker_stopping{false};
std::atomic<int> broker_wait_status{0};
std::function<void()> internal_failure_handler;
sx::comm::gre::Mode broker_mode = sx::comm::gre::Mode::disabled;
std::string broker_path;
volatile sig_atomic_t stop_requested = 0;

int unix_address(const std::string& path, sockaddr_un& address, socklen_t& length) {
    if(path.empty() || path.size() >= sizeof(address.sun_path)) {
        errno = path.empty() ? EINVAL : ENAMETOOLONG;
        return -1;
    }
    address = {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);
    return 0;
}

int connect_seqpacket(const std::string& path) {
    sockaddr_un address{};
    socklen_t length = 0;
    if(unix_address(path, address, length) != 0) return -1;
    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    if(::connect(fd, reinterpret_cast<sockaddr*>(&address), length) != 0) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int listen_seqpacket(const std::string& path) {
    sockaddr_un address{};
    socklen_t length = 0;
    if(unix_address(path, address, length) != 0) return -1;
    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    if(::bind(fd, reinterpret_cast<sockaddr*>(&address), length) != 0
       || ::listen(fd, 16) != 0) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

std::shared_ptr<SharedStats> make_shared_stats() {
    void* memory = ::mmap(nullptr, sizeof(SharedStats), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(memory == MAP_FAILED) return {};
    auto* value = new(memory) SharedStats();
    return {value, [](SharedStats* stats) {
        stats->~SharedStats();
        ::munmap(stats, sizeof(SharedStats));
    }};
}

void append_u64(std::string& output, std::uint64_t value) {
    for(int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffU));
}

std::uint64_t read_u64(const char* input) {
    std::uint64_t value = 0;
    for(unsigned i = 0; i < sizeof(value); ++i)
        value = (value << 8U) | static_cast<unsigned char>(input[i]);
    return value;
}

std::string encode_broker_stats(const SharedStats& stats) {
    std::string payload;
    payload.reserve(broker_stats_size);
    append_u64(payload, stats.received.load(std::memory_order_relaxed));
    append_u64(payload, stats.exported.load(std::memory_order_relaxed));
    append_u64(payload, stats.errors.load(std::memory_order_relaxed));
    return payload;
}

int decode_broker_stats(const std::string& payload, sx::comm::gre::Stats& output) {
    if(payload.size() != broker_stats_size) { errno = EPROTO; return -1; }
    output.received = read_u64(payload.data());
    output.exported = read_u64(payload.data() + sizeof(std::uint64_t));
    output.errors = read_u64(payload.data() + 2 * sizeof(std::uint64_t));
    return 0;
}

class TransportControl : public socle::traflog::GreTransport {
public:
    virtual int broker_stats(sx::comm::gre::Stats& output) = 0;
};

class SocketTransport final : public TransportControl {
public:
    SocketTransport(int fd, std::shared_ptr<SharedStats> counters)
        : client_(fd, std::chrono::seconds(2)), counters_(std::move(counters)) {
        client_.set_nonblocking();
    }

    bool submit(buffer const& frame) override {
        counters_->submitted.fetch_add(1, std::memory_order_relaxed);
        const std::string payload(reinterpret_cast<const char*>(frame.data()), frame.size());
        if(client_.notify(gre_frame_opcode, payload) == 0) return true;
        counters_->dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    int broker_stats(sx::comm::gre::Stats& output) override {
        sx::comm::Reply reply;
        if(client_.request(gre_stats_opcode, {}, -1, reply) != 0) return -1;
        return decode_broker_stats(reply.payload, output);
    }

private:
    sx::comm::Client client_;
    std::shared_ptr<SharedStats> counters_;
};

class ReconnectingTransport final : public TransportControl {
public:
    ReconnectingTransport(std::string path, int fd, std::shared_ptr<SharedStats> counters)
        : path_(std::move(path)), counters_(std::move(counters)), client_(make_client(fd)),
          worker_([this] { reconnect_loop(); }) {
        counters_->connected.store(true, std::memory_order_relaxed);
    }

    ~ReconnectingTransport() override {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
            client_.reset();
        }
        condition_.notify_one();
        if(worker_.joinable()) worker_.join();
        counters_->connected.store(false, std::memory_order_relaxed);
    }

    bool submit(buffer const& frame) override {
        counters_->submitted.fetch_add(1, std::memory_order_relaxed);
        std::shared_ptr<sx::comm::Client> client;
        {
            std::lock_guard lock(mutex_);
            client = client_;
        }
        if(client) {
            const std::string payload(reinterpret_cast<const char*>(frame.data()), frame.size());
            if(client->notify(gre_frame_opcode, payload) == 0) return true;
            disconnect(client);
        }
        counters_->dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    int broker_stats(sx::comm::gre::Stats& output) override {
        std::shared_ptr<sx::comm::Client> client;
        {
            std::lock_guard lock(mutex_);
            client = client_;
        }
        if(!client) { errno = ENOTCONN; return -1; }
        sx::comm::Reply reply;
        if(client->request(gre_stats_opcode, {}, -1, reply) != 0) {
            disconnect(client);
            return -1;
        }
        return decode_broker_stats(reply.payload, output);
    }

private:
    static std::shared_ptr<sx::comm::Client> make_client(int fd) {
        auto client = std::make_shared<sx::comm::Client>(fd, std::chrono::seconds(2));
        if(client->set_nonblocking() != 0) return {};
        return client;
    }

    void disconnect(const std::shared_ptr<sx::comm::Client>& expected) {
        {
            std::lock_guard lock(mutex_);
            if(client_ != expected) return;
            client_.reset();
            counters_->connected.store(false, std::memory_order_relaxed);
        }
        condition_.notify_one();
    }

    void reconnect_loop() {
        constexpr std::chrono::milliseconds delays[] = {
            std::chrono::milliseconds(100), std::chrono::milliseconds(500),
            std::chrono::seconds(1), std::chrono::seconds(5)
        };
        std::size_t delay = 0;
        for(;;) {
            std::shared_ptr<sx::comm::Client> current;
            {
                std::unique_lock lock(mutex_);
                if(stopping_) return;
                current = client_;
                if(!current) {
                    condition_.wait_for(lock, delays[delay], [this] { return stopping_; });
                    if(stopping_) return;
                }
            }

            if(current) {
                pollfd descriptor{current->native_handle(), POLLHUP | POLLERR, 0};
                const int result = ::poll(&descriptor, 1, 250);
                if(result > 0 && (descriptor.revents & (POLLHUP | POLLERR | POLLNVAL))) {
                    disconnect(current);
                }
                continue;
            }

            const int fd = connect_seqpacket(path_);
            if(fd < 0) {
                delay = std::min(delay + 1, std::size_t{3});
                continue;
            }
            auto replacement = make_client(fd);
            ::close(fd);
            if(!replacement) continue;
            {
                std::lock_guard lock(mutex_);
                if(stopping_) return;
                client_ = std::move(replacement);
                counters_->connected.store(true, std::memory_order_relaxed);
                counters_->reconnects.fetch_add(1, std::memory_order_relaxed);
            }
            delay = 0;
        }
    }

    std::string path_;
    std::shared_ptr<SharedStats> counters_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::shared_ptr<sx::comm::Client> client_;
    bool stopping_ = false;
    std::thread worker_;
};

class ExportOperation final : public sx::comm::Operation {
public:
    ExportOperation(sx::comm::gre::Profile profile, std::shared_ptr<SharedStats> counters)
        : exporter_(profile.family, profile.destination), counters_(std::move(counters)) {
        exporter_.ttl(profile.ttl);
        exporter_.bind_if(profile.bind_interface);
    }

    sx::comm::Reply execute(const sx::comm::Request& request) override {
        counters_->received.fetch_add(1, std::memory_order_relaxed);
        if(request.fd >= 0 || request.payload.empty()) {
            counters_->errors.fetch_add(1, std::memory_order_relaxed);
            return sx::comm::error_reply(EINVAL);
        }
        buffer frame(request.payload.size());
        frame.append(request.payload.data(), request.payload.size());
        if(exporter_.send_encapsulated(frame)) {
            counters_->exported.fetch_add(1, std::memory_order_relaxed);
            return {};
        }
        counters_->errors.fetch_add(1, std::memory_order_relaxed);
        return sx::comm::error_reply(errno);
    }

    bool one_way() const noexcept override { return true; }

private:
    socle::traflog::GreExporter exporter_;
    std::shared_ptr<SharedStats> counters_;
};

class StatsOperation final : public sx::comm::Operation {
public:
    explicit StatsOperation(std::shared_ptr<SharedStats> counters)
        : counters_(std::move(counters)) {}

    sx::comm::Reply execute(const sx::comm::Request& request) override {
        if(request.fd >= 0 || !request.payload.empty()) return sx::comm::error_reply(EINVAL);
        return {0, encode_broker_stats(*counters_), -1};
    }

private:
    std::shared_ptr<SharedStats> counters_;
};

int serve_connection(int fd, const sx::comm::gre::Profile& profile,
                     const std::shared_ptr<SharedStats>& counters,
                     const std::function<bool()>& stop = {}) {
    sx::comm::Server server(fd);
    if(server.register_operation(gre_frame_opcode,
                                 std::make_shared<ExportOperation>(profile, counters)) != 0) {
        return -1;
    }
    if(server.register_operation(gre_stats_opcode,
                                 std::make_shared<StatsOperation>(counters)) != 0) return -1;
    return stop ? server.run_until(stop) : server.run();
}

[[noreturn]] void broker_entry(int fd, sx::comm::gre::Profile profile,
                               std::shared_ptr<SharedStats> counters) {
    if(::setpgid(0, 0) != 0) ::_exit(EXIT_FAILURE);
    ::_exit(serve_connection(fd, profile, counters) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

void request_stop(int) { stop_requested = 1; }

} // namespace

namespace sx::comm::gre {

int start_local_broker(Profile profile) {
    std::lock_guard lock(state_mutex);
    if(broker_pid > 0 || installed_transport) { errno = EALREADY; return -1; }
    if(profile.destination.empty()) { errno = EINVAL; return -1; }
    int channels[2] = {-1, -1};
    if(socle::privsep::make_channel_pair(channels) != 0) return -1;
    auto counters = make_shared_stats();
    if(!counters) { ::close(channels[0]); ::close(channels[1]); return -1; }
    const pid_t child = ::fork();
    if(child < 0) {
        const int saved = errno; ::close(channels[0]); ::close(channels[1]); errno = saved; return -1;
    }
    if(child == 0) { ::close(channels[0]); broker_entry(channels[1], std::move(profile), counters); }
    ::close(channels[1]);
    auto sink = std::make_shared<SocketTransport>(channels[0], counters);
    ::close(channels[0]);
    shared_stats = std::move(counters);
    shared_stats->connected.store(true, std::memory_order_relaxed);
    installed_transport = std::move(sink);
    broker_pid = child;
    broker_mode = Mode::internal;
    broker_path.clear();
    broker_stopping.store(false, std::memory_order_relaxed);
    broker_monitor = std::thread([child] {
        int status = 0;
        pid_t result;
        do { result = ::waitpid(child, &status, 0); } while(result < 0 && errno == EINTR);
        broker_wait_status.store(result == child ? status : -1, std::memory_order_relaxed);
        std::function<void()> handler;
        {
            std::lock_guard lock(state_mutex);
            if(shared_stats) shared_stats->connected.store(false, std::memory_order_relaxed);
            if(!broker_stopping.load(std::memory_order_relaxed)) handler = internal_failure_handler;
        }
        if(handler) handler();
    });
    return 0;
}

int connect_external_broker(const std::string& path) {
    std::lock_guard lock(state_mutex);
    if(broker_pid > 0 || installed_transport) { errno = EALREADY; return -1; }
    const int fd = connect_seqpacket(path);
    if(fd < 0) return -1;
    auto counters = std::make_shared<SharedStats>();
    auto sink = std::make_shared<ReconnectingTransport>(path, fd, counters);
    ::close(fd);
    shared_stats = std::move(counters);
    installed_transport = std::move(sink);
    broker_mode = Mode::external;
    broker_path = path;
    return 0;
}

int stop_local_broker() {
    std::shared_ptr<socle::traflog::GreTransport> transport_to_close;
    bool owned = false;
    {
        std::lock_guard lock(state_mutex);
        broker_stopping.store(true, std::memory_order_relaxed);
        transport_to_close = std::move(installed_transport);
        owned = broker_pid > 0;
    }
    transport_to_close.reset();
    if(broker_monitor.joinable()) broker_monitor.join();
    const int status = broker_wait_status.load(std::memory_order_relaxed);
    {
        std::lock_guard lock(state_mutex);
        shared_stats.reset();
        broker_pid = -1;
        broker_mode = Mode::disabled;
        broker_path.clear();
    }
    if(!owned) return 0;
    return status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS ? 0 : -1;
}

int run_standalone_broker(const std::string& path, Profile profile) {
    if(profile.destination.empty()) { errno = EINVAL; return -1; }
    const int listener = listen_seqpacket(path);
    if(listener < 0) return -1;

    struct sigaction action{};
    action.sa_handler = request_stop;
    ::sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, nullptr);
    ::sigaction(SIGTERM, &action, nullptr);

    auto counters = std::make_shared<SharedStats>();
    int result = 0;
    while(!stop_requested) {
        const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if(client < 0) {
            if(errno == EINTR) continue;
            result = -1;
            break;
        }
        if(serve_connection(client, profile, counters, [] { return stop_requested != 0; }) < 0
           && errno != ECONNRESET) result = -1;
        ::close(client);
        if(result != 0) break;
    }
    const int saved = errno;
    ::close(listener);
    ::unlink(path.c_str());
    errno = saved;
    return result;
}

std::shared_ptr<socle::traflog::GreTransport> transport() {
    std::lock_guard lock(state_mutex);
    return installed_transport;
}

Stats stats() noexcept {
    std::lock_guard lock(state_mutex);
    if(!shared_stats) return {};
    return {shared_stats->submitted.load(std::memory_order_relaxed),
            shared_stats->dropped.load(std::memory_order_relaxed),
            shared_stats->received.load(std::memory_order_relaxed),
            shared_stats->exported.load(std::memory_order_relaxed),
            shared_stats->errors.load(std::memory_order_relaxed),
            shared_stats->reconnects.load(std::memory_order_relaxed),
            shared_stats->connected.load(std::memory_order_relaxed)};
}

int broker_stats(Stats& output) {
    std::shared_ptr<TransportControl> control;
    {
        std::lock_guard lock(state_mutex);
        control = std::dynamic_pointer_cast<TransportControl>(installed_transport);
    }
    if(!control) { errno = ENOTCONN; return -1; }
    Stats result;
    if(control->broker_stats(result) != 0) return -1;
    output = result;
    return 0;
}

Mode mode() noexcept {
    std::lock_guard lock(state_mutex);
    return broker_mode;
}

std::string external_path() {
    std::lock_guard lock(state_mutex);
    return broker_path;
}

void set_internal_failure_handler(std::function<void()> handler) {
    std::lock_guard lock(state_mutex);
    internal_failure_handler = std::move(handler);
}

pid_t owned_broker_pid() noexcept {
    std::lock_guard lock(state_mutex);
    return broker_pid;
}

} // namespace sx::comm::gre
