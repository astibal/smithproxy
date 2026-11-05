#pragma once

#include <nlohmann/json.hpp>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace cpu_monitor {
using Json = nlohmann::json;
struct Counter { uint64_t identity = 0, ticks = 0; };
// Subject 0 is the process aggregate; positive subjects are native TIDs.
using Counters = std::unordered_map<int, Counter>;
using Clock = std::function<double()>;
using Reader = std::function<Counters(int)>;
using Writer = std::function<void(const Json&)>;
std::string subject_name(int subject);
double monotonic_time();
double process_time();
Counters read_process(int pid);

struct Config {
    double interval = .05, window = .5, threshold = 80, timeout = 300;
    long hz = 100;
    void validate() const;
};

struct WindowResult {
    double before;
    std::unordered_map<int, double> percentages;
    std::vector<int> phase_ids; // -1 represents time outside a test.
};

// Histories retain departed threads only until their counters leave the window.
class RollingWindow {
    struct Entry { double time; Counters values; int phase; };
    double seconds_;
    long hz_;
    std::deque<Entry> history_;
    Counters values_;
    std::unordered_map<int, double> last_seen_;
public:
    RollingWindow(double seconds, long hz) : seconds_(seconds), hz_(hz) {}
    void reset(double now, const Counters& values, int phase);
    std::optional<WindowResult> advance(double now, const Counters& values, int phase);
};

// Clock, reader and sample sink are injected so the actual native accounting
// can be exercised with exact counter/time vectors and failing I/O.
class Recorder {
    Config config_;
    Clock clock_, cpu_clock_;
    Reader reader_;
    Writer writer_;
    int pid_ = 0, phase_ = -1;
    uint64_t identity_ = 0, samples_ = 0;
    double previous_time_ = 0, max_gap_ = 0, max_read_ = 0;
    double started_, cpu_started_;
    Counters previous_;
    RollingWindow continuous_, local_;
    Json phases_ = Json::array(), events_ = Json::array();
    std::pair<Counters, double> read_snapshot(int pid, std::optional<uint64_t> identity);
    void begin(const std::string& op, const Json& message, double now);
public:
    Recorder(Config config, Clock clock, Clock cpu_clock, Reader reader, Writer writer);
    bool attached() const { return pid_ != 0; }
    double sample();
    Json command(const Json& message);
    Json report(const std::string& error = {}) const;
};
} // namespace cpu_monitor
