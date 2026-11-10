#pragma once

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

// Transport diagnostics have no logging-library dependency: standalone helpers
// and auth-client users can install their own sink. Never pass message bodies,
// credentials or arbitrary reply text to this interface.
namespace sx::helper_debug {

enum class Service { comm, files, gre, webhook, sift, auth, count };
using Sink = void (*)(Service, int, std::uint64_t, std::string_view, std::string_view);
inline std::atomic<Sink> sink{nullptr};
using Filter = bool (*)(Service, int);
inline std::atomic<Filter> filter{nullptr};

inline bool enabled(Service service, int level = 8) noexcept {
    if (!sink.load(std::memory_order_acquire))
        return false;
    try {
        auto check = filter.load(std::memory_order_acquire);
        return !check || check(service, level);
    } catch (...) {
        return false;
    }
}

inline std::atomic_uint64_t sequence{0};
inline std::uint64_t next_id() noexcept {
    return ++sequence;
}

inline std::string field(std::string_view value) {
    std::string result;
    for (unsigned char c : value.substr(0, 160))
        result += c >= 33 && c < 127 && c != '\\' && c != '"' ? char(c) : '_';
    if (value.size() > 160)
        result += "...";
    return result;
}

inline void emit(Service service, std::uint64_t id, std::string_view event,
                 std::string_view detail = {}, int level = 8) noexcept {
    const int saved = errno;
    try {
        if (auto output = sink.load(std::memory_order_acquire))
            output(service, level, id, event, detail);
    } catch (...) {
    } // Diagnostics must not change transport behavior.
    errno = saved;
}

class Exchange {
  public:
    Exchange(Service service, std::string_view detail, std::uint64_t id = 0)
        : service_(service), id_(id ? id : next_id()) {
        emit(service_, id_, "begin", detail);
    }

    ~Exchange() noexcept {
        const int saved = errno;
        try {
            if (!finished_)
                finish("incomplete", "errno=" + std::to_string(saved));
        } catch (...) {
        }
        errno = saved;
    }

    std::uint64_t id() const noexcept {
        return id_;
    }

    Exchange(Exchange const &) = delete;
    Exchange &operator=(Exchange const &) = delete;

    void finish(std::string_view event, std::string detail = {}) {
        const int saved = errno;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - started_)
                                 .count();
        emit(service_, id_, event, detail + " elapsed_ms=" + std::to_string(elapsed));
        finished_ = true;
        errno = saved;
    }

  private:
    Service service_;
    std::uint64_t id_;
    std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
    bool finished_ = false;
};
} // namespace sx::helper_debug
