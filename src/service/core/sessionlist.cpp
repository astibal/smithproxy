#include <service/core/sessionlist.hpp>

#include <masterproxy.hpp>
#include <proxy/mitmproxy.hpp>
#include <service/core/smithproxy.hpp>

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
