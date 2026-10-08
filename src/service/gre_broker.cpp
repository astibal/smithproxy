#include <service/gre_broker.hpp>

#include <service/comm.hpp>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
#include <mutex>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr std::uint8_t gre_frame_opcode = 1;

struct SharedStats {
    std::atomic<std::uint64_t> submitted{0};
    std::atomic<std::uint64_t> dropped{0};
    std::atomic<std::uint64_t> exported{0};
    std::atomic<std::uint64_t> errors{0};
};

std::mutex state_mutex;
std::shared_ptr<SharedStats> shared_stats;
std::shared_ptr<socle::traflog::GreTransport> installed_transport;
pid_t broker_pid = -1;
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

class SocketTransport final : public socle::traflog::GreTransport {
public:
    SocketTransport(int fd, std::shared_ptr<SharedStats> counters)
        : client_(fd), counters_(std::move(counters)) { client_.set_nonblocking(); }

    bool submit(buffer const& frame) override {
        counters_->submitted.fetch_add(1, std::memory_order_relaxed);
        const std::string payload(reinterpret_cast<const char*>(frame.data()), frame.size());
        if(client_.notify(gre_frame_opcode, payload) == 0) return true;
        counters_->dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

private:
    sx::comm::Client client_;
    std::shared_ptr<SharedStats> counters_;
};

class ExportOperation final : public sx::comm::Operation {
public:
    ExportOperation(sx::comm::gre::Profile profile, std::shared_ptr<SharedStats> counters)
        : exporter_(profile.family, profile.destination), counters_(std::move(counters)) {
        exporter_.ttl(profile.ttl);
        exporter_.bind_if(profile.bind_interface);
    }

    sx::comm::Reply execute(const sx::comm::Request& request) override {
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

int serve_connection(int fd, const sx::comm::gre::Profile& profile,
                     const std::shared_ptr<SharedStats>& counters) {
    sx::comm::Server server(fd);
    if(server.register_operation(gre_frame_opcode,
                                 std::make_shared<ExportOperation>(profile, counters)) != 0) {
        return -1;
    }
    return server.run();
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
    installed_transport = std::move(sink);
    broker_pid = child;
    return 0;
}

int connect_external_broker(const std::string& path) {
    std::lock_guard lock(state_mutex);
    if(broker_pid > 0 || installed_transport) { errno = EALREADY; return -1; }
    const int fd = connect_seqpacket(path);
    if(fd < 0) return -1;
    auto counters = std::make_shared<SharedStats>();
    auto sink = std::make_shared<SocketTransport>(fd, counters);
    ::close(fd);
    shared_stats = std::move(counters);
    installed_transport = std::move(sink);
    return 0;
}

int stop_local_broker() {
    std::lock_guard lock(state_mutex);
    installed_transport.reset();
    shared_stats.reset();
    if(broker_pid <= 0) return 0;
    int status = 0;
    pid_t result;
    do { result = ::waitpid(broker_pid, &status, 0); } while(result < 0 && errno == EINTR);
    broker_pid = -1;
    return result >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS ? 0 : -1;
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
        if(serve_connection(client, profile, counters) < 0 && errno != ECONNRESET) result = -1;
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
            shared_stats->exported.load(std::memory_order_relaxed),
            shared_stats->errors.load(std::memory_order_relaxed)};
}

} // namespace sx::comm::gre
