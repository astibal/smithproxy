// Experimental Linux counter collector, not a replacement CPU gate.
// Usage: collector PID SAMPLES THREAD_STRIDE INTERVAL_MS
// stride 0: process only; 1: all samples; N: threads every N samples.
#include <chrono>
#include <ctime>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

struct Counter { unsigned long long start, ticks; char state; };

Counter read_stat(const std::string& path) {
    std::ifstream file(path);
    if (!file) throw std::system_error(errno, std::generic_category(), path);
    std::string text((std::istreambuf_iterator<char>(file)), {});
    if (file.bad()) throw std::runtime_error("stat read failed");
    const auto end = text.rfind(')');
    if (end == std::string::npos) throw std::runtime_error("invalid stat comm");
    std::istringstream fields(text.substr(end + 2));
    std::vector<std::string> values;
    for (std::string value; fields >> value;) values.push_back(value);
    if (values.size() < 20) throw std::runtime_error("short stat record");
    return {std::stoull(values[19]), std::stoull(values[11]) + std::stoull(values[12]), values[0][0]};
}

void emit_counter(std::ostream& out, const std::string& name, const Counter& c) {
    out << '"' << name << "\":[" << c.start << ',' << c.ticks << ']';
}

void snapshot(int pid, unsigned long long identity, bool threads) {
    const std::string root = "/proc/" + std::to_string(pid);
    const auto process = read_stat(root + "/stat");
    if (process.start != identity || process.state == 'Z' || process.state == 'X')
        throw std::runtime_error("target exited or PID reused");
    std::ostringstream out;
    out << '{';
    emit_counter(out, "process", process);
    if (threads) {
        DIR* directory = opendir((root + "/task").c_str());
        if (!directory) throw std::system_error(errno, std::generic_category(), "task directory");
        try {
            while (true) {
                errno = 0;
                auto* entry = readdir(directory);
                if (!entry) {
                    if (errno) throw std::system_error(errno, std::generic_category(), "readdir");
                    break;
                }
                const std::string tid = entry->d_name;
                if (tid.empty() || tid[0] == '.') continue;
                try {
                    const auto c = read_stat(root + "/task/" + tid + "/stat");
                    if (c.state == 'Z' || c.state == 'X') continue;
                    out << ',';
                    emit_counter(out, "thread:" + tid, c);
                } catch (const std::system_error& error) {
                    if (error.code().value() != ENOENT && error.code().value() != ESRCH) throw;
                }
            }
        } catch (...) { closedir(directory); throw; }
        closedir(directory);
    }
    std::cout << out.str() << "}\n";
    if (!std::cout) throw std::runtime_error("output failed");
}

int main(int argc, char** argv) {
    try {
        if (argc != 5) throw std::runtime_error("expected PID SAMPLES STRIDE INTERVAL_MS");
        const int pid = std::stoi(argv[1]), count = std::stoi(argv[2]);
        const int stride = std::stoi(argv[3]), interval = std::stoi(argv[4]);
        if (pid <= 0 || count <= 0 || stride < 0 || interval < 0) throw std::runtime_error("invalid arguments");
        const auto identity = read_stat("/proc/" + std::to_string(pid) + "/stat").start;
        const auto started = std::chrono::steady_clock::now();
        const auto cpu = std::clock();
        double max_read = 0;
        for (int i = 0; i < count; ++i) {
            const auto before = std::chrono::steady_clock::now();
            snapshot(pid, identity, stride && i % stride == 0);
            max_read = std::max(max_read, std::chrono::duration<double>(std::chrono::steady_clock::now() - before).count());
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
        std::cout.flush();
        if (!std::cout) throw std::runtime_error("flush failed");
        std::cerr << "{\"cpu\":" << double(std::clock() - cpu) / CLOCKS_PER_SEC
                  << ",\"wall\":" << std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count()
                  << ",\"max_read\":" << max_read << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
