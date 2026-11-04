#include "core.hpp"

#include <array>
#include <charconv>
#include <cerrno>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace cpu_monitor {
namespace {
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) {}
    ~Fd() { if (value >= 0) close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
[[noreturn]] void io_error(const std::string& operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}

uint64_t number(std::string_view field) {
    uint64_t value = 0;
    auto result = std::from_chars(field.data(), field.data() + field.size(), value);
    if (result.ec != std::errc{} || result.ptr != field.data() + field.size())
        throw std::runtime_error("invalid proc counter");
    return value;
}

struct Stat { Counter counter; char state; };
Stat read_stat(const std::string& path) {
    Fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.value < 0) io_error(path);
    std::array<char, 8192> buffer;
    size_t used = 0;
    while (used < buffer.size()) {
        const auto count = read(fd.value, buffer.data() + used, buffer.size() - used);
        if (count < 0) {
            if (errno == EINTR) continue;
            io_error(path); // ESRCH between open/read remains distinguishable.
        }
        if (!count) break;
        used += static_cast<size_t>(count);
    }
    if (used == buffer.size()) throw std::runtime_error("oversized proc stat");
    std::string_view text(buffer.data(), used);
    const auto end = text.rfind(')'); // comm can contain spaces, ')' and newline.
    if (end == std::string_view::npos) throw std::runtime_error("invalid proc stat");
    text.remove_prefix(end + 1);
    std::array<std::string_view, 20> fields;
    for (auto& field : fields) {
        const auto first = text.find_first_not_of(" \t\r\n");
        if (first == std::string_view::npos) throw std::runtime_error("short proc stat");
        text.remove_prefix(first);
        const auto length = text.find_first_of(" \t\r\n");
        field = text.substr(0, length);
        text.remove_prefix(field.size());
    }
    return {{number(fields[19]), number(fields[11]) + number(fields[12])}, fields[0][0]};
}

double clock_seconds(clockid_t clock) {
    timespec value{};
    if (clock_gettime(clock, &value)) io_error("clock_gettime");
    return static_cast<double>(value.tv_sec) + value.tv_nsec * 1e-9;
}
} // namespace

double monotonic_time() { return clock_seconds(CLOCK_MONOTONIC); }
double process_time() { return clock_seconds(CLOCK_PROCESS_CPUTIME_ID); }

Counters read_process(int pid) {
    const std::string root = "/proc/" + std::to_string(pid);
    const auto process = read_stat(root + "/stat");
    if (process.state == 'Z' || process.state == 'X')
        throw std::runtime_error("target exited");
    Counters result{{0, process.counter}};
    struct CloseDirectory { void operator()(DIR* p) const { closedir(p); } };
    std::unique_ptr<DIR, CloseDirectory> directory(opendir((root + "/task").c_str()));
    if (!directory) io_error("open task directory");
    while (true) {
        errno = 0;
        auto* entry = readdir(directory.get());
        if (!entry) {
            if (errno) io_error("read task directory");
            break;
        }
        if (entry->d_name[0] == '.') continue;
        const int tid = std::stoi(entry->d_name);
        try {
            const auto task = read_stat(root + "/task/" + entry->d_name + "/stat");
            if (task.state != 'Z' && task.state != 'X') result.emplace(tid, task.counter);
        } catch (const std::system_error& error) {
            if (error.code().value() != ENOENT && error.code().value() != ESRCH) throw;
        }
    }
    return result;
}
} // namespace cpu_monitor
