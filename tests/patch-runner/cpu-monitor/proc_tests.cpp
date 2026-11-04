// Native reader race tests. The linker wrapper acts at the actual read syscall,
// after production code has opened the task file, not at a duplicate parser.
#include "core.hpp"
#include <atomic>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {
std::string watched_path;
std::atomic<bool> release_worker{false};
std::thread* worker = nullptr;
int injected_errno = 0;
bool exited_during_read = false;
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

extern "C" ssize_t __real_read(int, void*, size_t);
extern "C" ssize_t __wrap_read(int fd, void* buffer, size_t count) {
    if (!watched_path.empty()) {
        char path[4096];
        const auto size = readlink(("/proc/self/fd/" + std::to_string(fd)).c_str(), path, sizeof path);
        if (size >= 0 && std::string(path, static_cast<size_t>(size)) == watched_path) {
            if (injected_errno) { errno = injected_errno; return -1; }
            release_worker = true;
            worker->join();
            // pthread_join observes exit before proc task teardown completes.
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            watched_path.clear();
            const auto result = __real_read(fd, buffer, count);
            exited_during_read = result < 0 && errno == ESRCH;
            return result;
        }
    }
    return __real_read(fd, buffer, count);
}

// Fortified glibc builds redirect read() to __read_chk. Exercise the same
// race under both toolchains, while preserving the buffer-bound check.
extern "C" ssize_t __wrap___read_chk(int fd, void* buffer, size_t count, size_t size) {
    if (count > size) std::abort();
    return __wrap_read(fd, buffer, count);
}

int main() {
    try {
        const int pid = getpid();
        for (bool permission_failure : {false, true}) {
            std::atomic<int> tid{0};
            release_worker = false;
            std::thread thread([&] {
                tid = static_cast<int>(syscall(SYS_gettid));
                while (!release_worker) std::this_thread::yield();
            });
            while (!tid) std::this_thread::yield();
            worker = &thread;
            watched_path = "/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid.load()) + "/stat";
            injected_errno = permission_failure ? EACCES : 0;
            bool propagated = false;
            cpu_monitor::Counters result;
            try { result = cpu_monitor::read_process(pid); }
            catch (const std::system_error& error) { propagated = error.code().value() == EACCES; }
            release_worker = true;
            if (thread.joinable()) thread.join();
            watched_path.clear();
            if (permission_failure) check(propagated, "access error was swallowed");
            else {
                check(exited_during_read, "did not reproduce ESRCH between open and read");
                check(!result.count(tid), "departed thread remained in snapshot");
            }
        }
        check(prctl(PR_SET_NAME, "odd ) name\n") == 0, "cannot set comm");
        check(cpu_monitor::read_process(pid).count(0) == 1, "unusual comm broke parser");
        const pid_t child = fork();
        check(child >= 0, "fork failed");
        if (!child) _exit(0);
        siginfo_t info{};
        check(waitid(P_PID, child, &info, WEXITED | WNOWAIT) == 0, "waitid failed");
        bool rejected = false;
        try { cpu_monitor::read_process(child); } catch (const std::exception&) { rejected = true; }
        waitpid(child, nullptr, 0);
        check(rejected, "zombie target was accepted");
        std::cout << "native ESRCH, access-error, unusual-comm and zombie tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
