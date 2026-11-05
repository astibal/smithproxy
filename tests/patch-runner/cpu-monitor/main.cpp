#include "core.hpp"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <system_error>
#include <unistd.h>

namespace cm = cpu_monitor;
namespace fs = std::filesystem;
using cm::Json;

namespace {
[[noreturn]] void io_error(const std::string& operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}
struct Fd {
    int value = -1;
    ~Fd() { if (value >= 0) close(value); }
    Fd() = default;
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

// Buffered samples keep formatting/storage separate from the measurement core.
// FINISH must close successfully before a report or successful ACK is published.
class Output {
    FILE* file_ = nullptr;
public:
    explicit Output(const fs::path& path) {
        file_ = fopen(path.c_str(), "wx");
        if (!file_) io_error("open output");
    }
    ~Output() { if (file_) fclose(file_); }
    void write(const Json& record, int indent = -1) {
        auto text = record.dump(indent, ' ', false, Json::error_handler_t::replace) + '\n';
        if (fwrite(text.data(), 1, text.size(), file_) != text.size()) io_error("write output");
    }
    void finish() {
        if (!file_) return;
        auto* file = file_;
        file_ = nullptr;
        if (fclose(file)) io_error("close output");
    }
};

struct SocketPath {
    std::string path;
    struct stat identity{};
    bool owned = false;
    ~SocketPath() {
        struct stat current{};
        if (owned && lstat(path.c_str(), &current) == 0 &&
            current.st_dev == identity.st_dev && current.st_ino == identity.st_ino)
            unlink(path.c_str());
    }
};

bool ready(int fd, short events, double deadline) {
    while (true) {
        const double remaining = deadline - cm::monotonic_time();
        if (remaining <= 0) return false;
        const double milliseconds = std::min(remaining * 1000, double(std::numeric_limits<int>::max()));
        pollfd item{fd, events, 0};
        const int result = poll(&item, 1, static_cast<int>(std::ceil(milliseconds)));
        if (result < 0) {
            if (errno == EINTR) continue;
            io_error("poll");
        }
        if (result) return true; // HUP/ERR are handled by recv/send as failures.
    }
}

void send_reply(int connection, const Json& reply, double timeout) {
    const auto packet = reply.dump(-1, ' ', false, Json::error_handler_t::replace);
    const double deadline = cm::monotonic_time() + timeout;
    while (true) {
        if (!ready(connection, POLLOUT, deadline)) throw std::runtime_error("reply deadline expired");
        const auto count = send(connection, packet.data(), packet.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            io_error("send reply");
        }
        if (static_cast<size_t>(count) != packet.size()) throw std::runtime_error("short reply");
        return;
    }
}

void publish(const fs::path& directory, const Json& report) {
    const auto temporary = directory / "report.json.tmp";
    Output output(temporary);
    output.write(report, 2);
    output.finish();
    fs::rename(temporary, directory / "report.json");
}

struct Options {
    cm::Config config;
    std::string socket;
    fs::path output;
};
Options options(int argc, char** argv) {
    Options result;
    result.config.hz = sysconf(_SC_CLK_TCK);
    for (int i = 1; i < argc; ++i) {
        const std::string name = argv[i];
        if (name == "--help") {
            std::cout << "smithproxy-cpu-monitor --socket PATH --output NEW_DIRECTORY\n"
                         "  --interval-ms 50 --window-ms 500 --suspect-percent 80 --control-timeout 300\n";
            std::exit(0);
        }
        if (++i >= argc) throw std::runtime_error("missing option value");
        const std::string value = argv[i];
        if (name == "--socket") result.socket = value;
        else if (name == "--output") result.output = value;
        else {
            size_t used = 0;
            const double number = std::stod(value, &used);
            if (used != value.size()) throw std::runtime_error("invalid numeric option");
            if (name == "--interval-ms") result.config.interval = number / 1000;
            else if (name == "--window-ms") result.config.window = number / 1000;
            else if (name == "--suspect-percent") result.config.threshold = number;
            else if (name == "--control-timeout") result.config.timeout = number;
            else throw std::runtime_error("unknown option: " + name);
        }
    }
    result.config.validate();
    if (result.socket.empty() || result.output.empty()) throw std::runtime_error("socket and output required");
    return result;
}

int serve(const Options& args) {
    if (!args.output.parent_path().empty()) fs::create_directories(args.output.parent_path());
    if (!fs::create_directory(args.output)) throw std::runtime_error("output directory already exists");
    Output samples(args.output / "samples.jsonl");
    cm::Recorder recorder(args.config, cm::monotonic_time, cm::process_time,
                          cm::read_process, [&](const Json& sample) { samples.write(sample); });
    Fd listener, connection;
    SocketPath socket_path{args.socket, {}, false};
    try {
        listener.value = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (listener.value < 0) io_error("socket");
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        if (args.socket.size() >= sizeof address.sun_path) throw std::runtime_error("socket path too long");
        std::memcpy(address.sun_path, args.socket.c_str(), args.socket.size() + 1);
        if (bind(listener.value, reinterpret_cast<sockaddr*>(&address), sizeof address)) io_error("bind");
        if (lstat(args.socket.c_str(), &socket_path.identity)) io_error("socket stat");
        socket_path.owned = true;
        if (chmod(args.socket.c_str(), 0600) || listen(listener.value, 1)) io_error("listen");
        if (!ready(listener.value, POLLIN, cm::monotonic_time() + args.config.timeout))
            throw std::runtime_error("control deadline expired before connection");
        connection.value = accept4(listener.value, nullptr, nullptr, SOCK_CLOEXEC);
        if (connection.value < 0) io_error("accept");

        double last_control = cm::monotonic_time(), next_sample = last_control + args.config.interval;
        while (true) {
            const double deadline = last_control + args.config.timeout;
            if (cm::monotonic_time() >= deadline) throw std::runtime_error("control deadline expired");
            if (ready(connection.value, POLLIN, std::min(next_sample, deadline))) {
                char buffer[65536];
                const auto count = recv(connection.value, buffer, sizeof buffer, MSG_TRUNC | MSG_DONTWAIT);
                if (count < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    io_error("receive control");
                }
                if (!count) throw std::runtime_error("controller disconnected before FINISH");
                if (count > static_cast<ssize_t>(sizeof buffer)) throw std::runtime_error("control packet too large");
                const auto message = Json::parse(buffer, buffer + count);
                auto reply = recorder.command(message);
                last_control = cm::monotonic_time();
                if (message.at("op") == "FINISH") {
                    samples.finish();
                    const auto report = recorder.report();
                    publish(args.output, report);
                    reply["ok"] = true;
                    reply["verdict"] = report["verdict"];
                    send_reply(connection.value, reply, args.config.timeout);
                    return report["verdict"] == "PASS" ? 0 : 1;
                }
                reply["ok"] = true;
                send_reply(connection.value, reply, args.config.timeout);
            }
            if (cm::monotonic_time() >= next_sample) {
                if (recorder.attached()) recorder.sample();
                next_sample = cm::monotonic_time() + args.config.interval;
            }
        }
    } catch (const std::exception& failure) {
        std::string error = failure.what();
        try { samples.finish(); } catch (const std::exception& e) { error += std::string("; ") + e.what(); }
        try { publish(args.output, recorder.report(error)); }
        catch (const std::exception& e) { std::cerr << "cannot publish error report: " << e.what() << '\n'; }
        if (connection.value >= 0) {
            try { send_reply(connection.value, {{"ok", false}, {"error", error}}, std::min(1.0, args.config.timeout)); }
            catch (const std::exception&) { /* A lost controller cannot receive an error. */ }
        }
        std::cerr << error << '\n';
        return 2;
    }
}
} // namespace

int main(int argc, char** argv) {
    try { return serve(options(argc, argv)); }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 2; }
}
