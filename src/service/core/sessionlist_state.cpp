#include <service/core/sessionlist.hpp>

#include <sstream>

SessionList::version_type SessionList::next_version() noexcept {
    static std::atomic<version_type> version{0};
    return version.fetch_add(1, std::memory_order_relaxed) + 1;
}

SessionList::SessionList(std::size_t workers, text_renderer renderer)
    : version_(next_version()), kind_(kind::text), text_renderer_(std::move(renderer)),
      text_fragments_(workers), origins_(workers), completed_(workers, false), remaining_(workers) {}

SessionList::SessionList(std::size_t workers, json_renderer renderer)
    : version_(next_version()), kind_(kind::json), json_renderer_(std::move(renderer)),
      json_fragments_(workers, nlohmann::json::array()), origins_(workers),
      completed_(workers, false), remaining_(workers) {}

std::shared_ptr<SessionList> SessionList::text(std::size_t workers, text_renderer renderer) {
    return std::shared_ptr<SessionList>(new SessionList(workers, std::move(renderer)));
}

std::shared_ptr<SessionList> SessionList::json(std::size_t workers, json_renderer renderer) {
    return std::shared_ptr<SessionList>(new SessionList(workers, std::move(renderer)));
}

bool SessionList::wait_for(std::chrono::milliseconds timeout) const {
    if (complete()) return true;
    std::unique_lock lock(completion_lock_);
    return completion_cv_.wait_for(lock, timeout, [this] { return complete(); });
}

void SessionList::prepare_slot(std::size_t slot, std::string const& origin) {
    std::lock_guard lock(completion_lock_);
    origins_.at(slot) = origin;
}

void SessionList::finish_slot(std::size_t slot) {
    {
        std::lock_guard lock(completion_lock_);
        if (completed_.at(slot)) return;
        completed_[slot] = true;
    }
    if (remaining_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        std::lock_guard lock(completion_lock_);
        completion_cv_.notify_all();
    }
}

void SessionList::complete_empty_slot(std::size_t slot) {
    finish_slot(slot);
}

std::string SessionList::pending_origins() const {
    std::lock_guard lock(completion_lock_);
    std::stringstream result;
    for (std::size_t slot = 0; slot < completed_.size(); ++slot) {
        if (!completed_[slot]) result << (result.tellp() > 0 ? ", " : "") << origins_[slot];
    }
    return result.str();
}

std::string SessionList::text_result() const {
    std::stringstream result;
    for (auto const& fragment : text_fragments_) result << fragment;
    return result.str();
}

nlohmann::json SessionList::json_result() const {
    auto result = nlohmann::json::array();
    for (auto const& fragment : json_fragments_) {
        for (auto const& session : fragment) result.push_back(session);
    }
    return result;
}
