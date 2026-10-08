#include <service/api/api_broker.hpp>

#include <service/cli/cli_broker.hpp>

#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <mutex>
#include <signal.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

std::mutex state_mutex;
int core_listener = -1;
pid_t broker_pid = -1;
std::string owned_path;
std::thread broker_monitor;
std::atomic<bool> stopping{false};
std::atomic<int> wait_status{0};
std::function<void()> failure_handler;
sx::comm::stream::SharedStats* shared_stats = nullptr;

} // namespace

namespace sx::comm::api {

int start_internal_broker(Profile profile) {
    std::lock_guard lock(state_mutex);
    if(core_listener >= 0 || broker_pid > 0) { errno = EALREADY; return -1; }
    if(profile.allowed_ips.empty()) profile.allowed_ips.emplace_back("*");
    shared_stats = sx::comm::stream::create_shared_stats();
    if(!shared_stats) return -1;
    const std::string path = "@smithproxy-api-" + std::to_string(::getpid());
    core_listener = sx::comm::stream::create_unix_listener(path);
    if(core_listener < 0) { sx::comm::stream::destroy_shared_stats(shared_stats); shared_stats = nullptr; return -1; }
    const pid_t child = ::fork();
    if(child < 0) {
        const int saved = errno; ::close(core_listener); core_listener = -1;
        sx::comm::stream::destroy_shared_stats(shared_stats); shared_stats = nullptr;
        errno = saved; return -1;
    }
    if(child == 0) {
        ::close(core_listener);
        sx::comm::stream::BrokerServer server({std::move(profile.listen_address),
                                               profile.listen_port, path, {},
                                               std::move(profile.allowed_ips),
                                               std::move(profile.bind_interface), 256}, shared_stats);
        ::_exit(server.run() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    broker_pid = child;
    stopping.store(false, std::memory_order_relaxed);
    broker_monitor = std::thread([child] {
        int status = 0;
        pid_t result;
        do { result = ::waitpid(child, &status, 0); } while(result < 0 && errno == EINTR);
        wait_status.store(result == child ? status : -1, std::memory_order_relaxed);
        std::function<void()> handler;
        {
            std::lock_guard lock(state_mutex);
            if(!stopping.load(std::memory_order_relaxed)) handler = failure_handler;
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

int stop_broker() {
    pid_t child = -1;
    {
        std::lock_guard lock(state_mutex);
        stopping.store(true, std::memory_order_relaxed);
        if(core_listener >= 0) { ::close(core_listener); core_listener = -1; }
        if(!owned_path.empty()) { ::unlink(owned_path.c_str()); owned_path.clear(); }
        child = broker_pid;
    }
    if(child > 0) ::kill(child, SIGTERM);
    if(broker_monitor.joinable()) broker_monitor.join();
    const int status = wait_status.load(std::memory_order_relaxed);
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
    failure_handler = std::move(handler);
}

sx::comm::stream::Stats stats() noexcept {
    std::lock_guard lock(state_mutex);
    return sx::comm::stream::snapshot(shared_stats);
}

bool uses_external_broker() noexcept { std::lock_guard lock(state_mutex); return !owned_path.empty(); }
std::string external_path() { std::lock_guard lock(state_mutex); return owned_path; }

} // namespace sx::comm::api
