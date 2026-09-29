#include <service/reload/file_reload_service.hpp>

#include <algorithm>
#include <vector>

namespace sx::reload {

FileReloadService::~FileReloadService() {
    stop();
}

FileReloadService::resource_id FileReloadService::add(
        std::shared_ptr<ReloadableResourceBase> resource,
        std::chrono::milliseconds interval) {
    if(not resource) return 0;
    if(interval <= std::chrono::milliseconds::zero()) interval = std::chrono::milliseconds{1};

    std::lock_guard lock(lock_);
    auto const id = next_id_++;
    resources_.emplace(id, Entry{std::move(resource), interval, clock::now(), true});
    wake_.notify_all();
    return id;
}

bool FileReloadService::remove(resource_id id) {
    std::lock_guard lock(lock_);
    auto const removed = resources_.erase(id) != 0;
    if(removed) wake_.notify_all();
    return removed;
}

bool FileReloadService::request_reload(resource_id id) {
    std::lock_guard lock(lock_);
    auto found = resources_.find(id);
    if(found == resources_.end()) return false;
    found->second.force = true;
    found->second.next_check = clock::now();
    wake_.notify_all();
    return true;
}

void FileReloadService::start() {
    std::lock_guard lock(lock_);
    if(thread_.joinable()) return;
    stopping_ = false;
    running_.store(true, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
}

void FileReloadService::stop() {
    {
        std::lock_guard lock(lock_);
        if(not thread_.joinable()) return;
        stopping_ = true;
        wake_.notify_all();
    }
    thread_.join();
    running_.store(false, std::memory_order_release);
}

void FileReloadService::run() {
    struct DueResource {
        std::shared_ptr<ReloadableResourceBase> resource;
        bool force;
    };

    std::unique_lock lock(lock_);
    while(not stopping_) {
        auto const now = clock::now();
        std::vector<DueResource> due;
        auto next_wake = clock::time_point::max();

        for(auto& [id, entry] : resources_) {
            (void)id;
            if(entry.force or entry.next_check <= now) {
                due.push_back({entry.resource, entry.force});
                entry.force = false;
                entry.next_check = now + entry.interval;
            }
            next_wake = std::min(next_wake, entry.next_check);
        }

        if(not due.empty()) {
            lock.unlock();
            for(auto& item : due) {
                try {
                    if(item.force) item.resource->reload_now();
                    else item.resource->poll();
                } catch(...) {
                    // A third-party ReloadableResourceBase implementation must
                    // not terminate the shared reload worker. Typed resources
                    // convert parser exceptions into ReloadResult::failed.
                }
            }
            lock.lock();
            continue;
        }

        if(next_wake == clock::time_point::max()) {
            wake_.wait(lock);
        } else {
            wake_.wait_until(lock, next_wake);
        }
    }
}

} // namespace sx::reload
