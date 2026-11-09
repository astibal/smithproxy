#include "core.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace cpu_monitor {
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
double positive(const Json& value) {
    require(value.is_number(), "value must be a positive number");
    const double result = value.get<double>();
    require(std::isfinite(result) && result > 0, "value must be finite and positive");
    return result;
}
Json phase_id(int phase) { return phase < 0 ? Json(nullptr) : Json(phase); }
}

std::string subject_name(int subject) {
    return subject == 0 ? "process" : "thread:" + std::to_string(subject);
}

void Config::validate() const {
    positive(interval); positive(window); positive(threshold); positive(timeout);
    require(hz > 0, "invalid clock tick frequency");
    require(interval <= window / 10, "window must contain at least ten configured sample intervals");
}

// --- Rolling windows: continuous observations and phase-local CPU gates ---

void RollingWindow::reset(double now, const Counters& values, int phase) {
    history_.clear();
    values_ = values;
    last_seen_.clear();
    for (const auto& item : values) last_seen_[item.first] = now;
    history_.push_back({now, values, phase});
}

std::optional<WindowResult> RollingWindow::advance(double now, const Counters& values, int phase) {
    for (const auto& [subject, counter] : values) {
        values_[subject] = counter;
        last_seen_[subject] = now;
    }
    history_.push_back({now, values_, phase});
    while (history_.size() > 1 && now - history_[1].time >= seconds_) history_.pop_front();
    const auto& baseline = history_.front();
    const double elapsed = now - baseline.time;
    if (elapsed < seconds_) return std::nullopt;
    WindowResult result{baseline.time, {}, {}};
    for (const auto& [subject, counter] : values_) {
        auto previous = baseline.values.find(subject);
        uint64_t ticks = 0;
        if (previous != baseline.values.end() && previous->second.identity == counter.identity)
            ticks = previous->second.ticks;
        require(counter.ticks >= ticks, "CPU counter moved backwards in window");
        result.percentages[subject] = 100.0 * (counter.ticks - ticks) / hz_ / elapsed;
    }
    for (const auto& entry : history_) {
        if (std::find(result.phase_ids.begin(), result.phase_ids.end(), entry.phase) == result.phase_ids.end())
            result.phase_ids.push_back(entry.phase);
    }
    for (auto it = last_seen_.begin(); it != last_seen_.end();) {
        if (!values.count(it->first) && it->second <= baseline.time) {
            values_.erase(it->first);
            it = last_seen_.erase(it);
        } else ++it;
    }
    return result;
}

// --- Recorder: measurements, raw evidence and control transitions ---

Recorder::Recorder(Config config, Clock clock, Clock cpu_clock, Reader reader, Writer writer)
    : config_(config), clock_(std::move(clock)), cpu_clock_(std::move(cpu_clock)),
      reader_(std::move(reader)), writer_(std::move(writer)),
      started_(clock_()), cpu_started_(cpu_clock_()),
      continuous_(config.window, config.hz), local_(config.window, config.hz) {
    config_.validate();
}

std::pair<Counters, double> Recorder::read_snapshot(int pid, std::optional<uint64_t> identity) {
    const double before = clock_();
    auto values = reader_(pid);
    const double now = clock_();
    const double duration = now - before;
    max_read_ = std::max(max_read_, duration);
    require(duration >= 0 && duration <= config_.interval,
            "snapshot duration exceeds sampling interval or clock moved backwards");
    require(values.count(0), "missing process aggregate");
    require(!identity || values.at(0).identity == *identity, "target exited or PID was reused");
    return {std::move(values), now};
}

double Recorder::sample() {
    auto [values, now] = read_snapshot(pid_, identity_);
    const double gap = now - previous_time_;
    max_gap_ = std::max(max_gap_, gap);
    require(gap >= 0 && gap <= 2 * config_.interval, "sampling gap too large or clock moved backwards");

    Json percentages = Json::object(), counters = Json::object();
    for (const auto& [subject, counter] : values) {
        const auto name = subject_name(subject);
        counters[name] = {counter.identity, counter.ticks};
        const auto previous = previous_.find(subject);
        if (previous != previous_.end() && previous->second.identity == counter.identity) {
            require(counter.ticks >= previous->second.ticks, "CPU counter moved backwards");
            if (gap > 0) percentages[name] = 100.0 * (counter.ticks - previous->second.ticks) / config_.hz / gap;
        }
    }
    writer_({{"time", now}, {"phase", phase_id(phase_)}, {"cpu", percentages},
             {"counters", counters}, {"gap", gap}});
    ++samples_;
    previous_ = std::move(values);
    previous_time_ = now;

    if (auto window = continuous_.advance(now, previous_, phase_)) {
        Json ids = Json::array();
        for (int id : window->phase_ids) ids.push_back(phase_id(id));
        for (const auto& [subject, cpu] : window->percentages) {
            if (cpu < config_.threshold) continue;
            // Time overlap is evidence, not causality. Never label a crossing
            // window solely with the last test that happened to be active.
            events_.push_back({{"scope", "monitor"},
                {"phase", ids.size() == 1 ? ids.front() : Json(nullptr)},
                {"phase_ids", ids}, {"attribution", "temporal_overlap_only"},
                {"subject", subject_name(subject)}, {"start", window->before},
                {"end", now}, {"cpu", cpu}, {"suspect", true}, {"violation", false}});
        }
    }
    if (phase_ >= 0) {
        if (auto window = local_.advance(now, previous_, phase_)) {
            auto& phase = phases_.at(phase_);
            for (const auto& [subject, cpu] : window->percentages) {
                const auto name = subject_name(subject);
                auto& peaks = phase["peak_window_cpu"];
                peaks[name] = std::max(cpu, peaks.value(name, 0.0));
                if (phase["mode"] != "observe" && cpu >= phase["limit"].get<double>()) {
                    phase["verdict"] = "FAIL";
                    events_.push_back({{"scope", "phase"}, {"phase", phase_},
                        {"attribution", "temporal_overlap_only"},
                        {"subject", name}, {"start", window->before}, {"end", now},
                        {"cpu", cpu}, {"suspect", false}, {"violation", true}});
                }
            }
        }
    }
    return now;
}

void Recorder::begin(const std::string& op, const Json& message, double now) {
    require(op != "BEGIN" || phase_ < 0, "BEGIN requires no active test");
    require(op != "PHASE" || phase_ >= 0, "PHASE requires an active test");
    const auto mode = message.value("mode", std::string("observe"));
    require(mode == "observe" || mode == "idle" || mode == "bounded", "unknown CPU mode");
    const auto name = message.at("name").get<std::string>();
    require(!name.empty(), "name must be nonempty text");
    const double limit = positive(message.value("limit", Json(mode == "idle" ? 20 : 80)));
    if (phase_ >= 0) phases_.at(phase_)["end"] = now;
    phase_ = static_cast<int>(phases_.size());
    phases_.push_back({{"id", phase_}, {"name", name}, {"mode", mode},
        {"limit", limit}, {"start", now}, {"verdict", mode == "observe" ? "OBSERVED" : "PASS"},
        {"peak_window_cpu", Json::object()}});
    local_.reset(now, previous_, phase_);
}

Json Recorder::command(const Json& message) {
    const auto op = message.at("op").get<std::string>();
    if (op == "ATTACH") {
        require(!attached(), "already attached");
        const auto& value = message.at("pid");
        require(value.is_number_integer(), "PID must be an integer");
        require(value > 0 && value <= std::numeric_limits<int>::max(), "PID out of range");
        const int pid = value.get<int>();
        auto [values, now] = read_snapshot(pid, std::nullopt);
        identity_ = values.at(0).identity;
        previous_ = std::move(values);
        previous_time_ = now;
        pid_ = pid;
        continuous_.reset(now, previous_, -1);
        return Json::object();
    }
    require(attached(), "ATTACH required");
    const double now = sample();
    if (op == "BEGIN" || op == "PHASE") begin(op, message, now);
    else if (op == "END") {
        require(phase_ >= 0, "no active test");
        phases_.at(phase_)["end"] = now;
        phases_.at(phase_)["test_result"] = message.value("result", Json(nullptr));
        phase_ = -1;
        local_.reset(now, {}, -1);
    } else if (op == "FINISH") {
        require(phase_ < 0 && !phases_.empty(), "FINISH requires at least one completed test");
    } else throw std::runtime_error("unknown operation: " + op);
    return {{"time", now}};
}

Json Recorder::report(const std::string& error) const {
    bool incomplete = false, failed = false;
    for (const auto& phase : phases_) {
        incomplete |= phase["mode"] != "observe" && phase["peak_window_cpu"].empty();
        failed |= phase["verdict"] == "FAIL";
    }
    const std::string issue = !error.empty() ? error : incomplete ? "required phase shorter than evaluation window" : "";
    return {{"verdict", !issue.empty() ? "ERROR" : failed ? "FAIL" : "PASS"},
        {"error", issue.empty() ? Json(nullptr) : Json(issue)},
        {"pid", pid_ ? Json(pid_) : Json(nullptr)}, {"start_ticks", pid_ ? Json(identity_) : Json(nullptr)},
        {"interval", config_.interval}, {"window", config_.window}, {"suspect_threshold", config_.threshold},
        {"clock_ticks_per_second", config_.hz}, {"max_allowed_sample_gap", 2 * config_.interval},
        {"thread_interval_accounting", "lower_bound"}, {"samples", samples_}, {"max_sample_gap", max_gap_},
        {"max_snapshot_duration", max_read_}, {"max_allowed_snapshot_duration", config_.interval},
        {"monitor_cpu_seconds", cpu_clock_() - cpu_started_}, {"elapsed", clock_() - started_},
        {"phases", phases_}, {"events", events_}, {"implementation", "cpp"},
        {"attribution", "temporal_overlap_only"}};
}
} // namespace cpu_monitor
