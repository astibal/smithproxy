#include <service/core/sessionlist.hpp>

#include <masterproxy.hpp>
#include <proxy/mitmproxy.hpp>
#include <service/core/smithproxy.hpp>

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
        completed_.at(slot) = true;
    }
    if (remaining_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        std::lock_guard lock(completion_lock_);
        completion_cv_.notify_all();
    }
}

void SessionList::complete_empty_slot(std::size_t slot) {
    finish_slot(slot);
}

void SessionList::collect(MasterProxy& master, std::size_t slot, std::string const& origin) {
    std::stringstream text;
    nlohmann::json json = nlohmann::json::array();
    for (auto const& base_proxy : master.proxies()) {
        if (!base_proxy) continue;

        auto* proxy = dynamic_cast<MitmProxy*>(base_proxy.get());
        if (!proxy) continue;

        if (kind_ == kind::text) {
            if (auto rendered = text_renderer_(proxy); rendered) text << *rendered << '\n';
        } else {
            if (auto rendered = json_renderer_(proxy); rendered) {
                (*rendered)["origin"] = origin;
                json.push_back(std::move(*rendered));
            }
        }
    }

    if (kind_ == kind::text) text_fragments_.at(slot) = std::move(text).str();
    else json_fragments_.at(slot) = std::move(json);
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

void SessionListConsumer::enqueue_session_list(std::shared_ptr<SessionList> request,
                                               std::size_t slot,
                                               std::string origin) {
    std::lock_guard lock(pending_lock_);
    pending_.push_back({std::move(request), slot, std::move(origin)});
}

void SessionListConsumer::process_session_lists(MasterProxy& master) {
    std::deque<pending_request> pending;
    {
        std::lock_guard lock(pending_lock_);
        pending.swap(pending_);
    }
    for (auto& item : pending) item.request->collect(master, item.slot, item.origin);
}

namespace {
template<class List, class Callback>
void for_each_worker(List const& listeners, char const* origin, bool wake, Callback&& callback) {
    for (auto const& acceptor : listeners) {
        for (auto const& worker : acceptor->tasks()) callback(*worker.second, origin);
        if (wake) acceptor->hint_wake_all();
    }
}

template<class Callback>
void all_session_workers(bool wake, Callback&& callback) {
    auto const& instance = SmithProxy::instance();
    for_each_worker(instance.plain_proxies, "plain acceptor", wake, callback);
    for_each_worker(instance.ssl_proxies, "tls acceptor", wake, callback);
    for_each_worker(instance.udp_proxies, "udp receiver", wake, callback);
    for_each_worker(instance.dtls_proxies, "dtls receiver", wake, callback);
    for_each_worker(instance.socks_proxies, "socks acceptor", wake, callback);
    for_each_worker(instance.socks_udp_proxies, "socks receiver", wake, callback);
    for_each_worker(instance.redir_plain_proxies, "plain redirect acceptor", wake, callback);
    for_each_worker(instance.redir_udp_proxies, "dns redirect receiver", wake, callback);
    for_each_worker(instance.redir_ssl_proxies, "tls redirect acceptor", wake, callback);
}
} // namespace

std::size_t session_list_worker_count() {
    std::size_t count = 0;
    all_session_workers(false, [&count](auto&, char const*) { ++count; });
    return count;
}

void dispatch_session_list(std::shared_ptr<SessionList> const& request) {
    std::size_t slot = 0;
    all_session_workers(true, [&](auto& worker, char const* origin) {
        request->prepare_slot(slot, origin);
        bool empty = false;
        {
            auto lock = std::scoped_lock(worker.proxy_lock());
            empty = worker.proxies().empty();
        }
        if (empty) request->complete_empty_slot(slot++);
        else worker.enqueue_session_list(request, slot++, origin);
    });
}
