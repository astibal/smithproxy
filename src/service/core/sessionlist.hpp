#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

class MasterProxy;
class MitmProxy;

class SessionList {
public:
    using version_type = std::uint64_t;
    using text_renderer = std::function<std::optional<std::string>(MitmProxy*)>;
    using json_renderer = std::function<std::optional<nlohmann::json>(MitmProxy*)>;

    static std::shared_ptr<SessionList> text(std::size_t workers, text_renderer renderer);
    static std::shared_ptr<SessionList> json(std::size_t workers, json_renderer renderer);

    version_type version() const noexcept { return version_; }
    bool wait_for(std::chrono::milliseconds timeout) const;
    bool complete() const noexcept { return remaining_.load(std::memory_order_acquire) == 0; }

    std::string text_result() const;
    nlohmann::json json_result() const;
    std::size_t skipped_spread() const noexcept { return skipped_spread_.load(std::memory_order_relaxed); }

    void collect(MasterProxy& master, std::size_t slot, std::string const& origin);

private:
    enum class kind { text, json };

    SessionList(std::size_t workers, text_renderer renderer);
    SessionList(std::size_t workers, json_renderer renderer);
    void finish_slot();

    static version_type next_version() noexcept;

    const version_type version_;
    const kind kind_;
    text_renderer text_renderer_;
    json_renderer json_renderer_;
    std::vector<std::string> text_fragments_;
    std::vector<nlohmann::json> json_fragments_;
    std::atomic_size_t remaining_;
    std::atomic_size_t skipped_spread_{0};
    mutable std::mutex completion_lock_;
    mutable std::condition_variable completion_cv_;
};

class SessionListConsumer {
public:
    void enqueue_session_list(std::shared_ptr<SessionList> request,
                              std::size_t slot,
                              std::string origin);

protected:
    void process_session_lists(MasterProxy& master);

private:
    struct pending_request {
        std::shared_ptr<SessionList> request;
        std::size_t slot;
        std::string origin;
    };

    std::mutex pending_lock_;
    std::deque<pending_request> pending_;
};

std::size_t session_list_worker_count();
void dispatch_session_list(std::shared_ptr<SessionList> const& request);
