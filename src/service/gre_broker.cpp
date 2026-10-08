#include <service/gre_broker.hpp>

#include <service/comm.hpp>

#include <atomic>
#include <cerrno>
#include <memory>
#include <mutex>
#include <signal.h>
#include <sys/mman.h>
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

[[noreturn]] void broker_entry(int fd, sx::comm::gre::Profile profile,
                               std::shared_ptr<SharedStats> counters) {
    if(::setpgid(0, 0) != 0) ::_exit(EXIT_FAILURE);
    sx::comm::Server server(fd);
    if(server.register_operation(gre_frame_opcode,
                                 std::make_shared<ExportOperation>(std::move(profile),
                                                                   std::move(counters))) != 0) {
        ::_exit(EXIT_FAILURE);
    }
    ::close(fd);
    ::_exit(server.run() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

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
