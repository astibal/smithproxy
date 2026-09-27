#pragma once

#include <service/reload/reloadable_resource.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace sx::reload {

class FileReloadService {
public:
    using resource_id = std::uint64_t;

    FileReloadService() = default;
    ~FileReloadService();

    FileReloadService(FileReloadService const&) = delete;
    FileReloadService& operator=(FileReloadService const&) = delete;

    resource_id add(std::shared_ptr<ReloadableResourceBase> resource,
                    std::chrono::milliseconds interval);
    bool remove(resource_id id);
    bool request_reload(resource_id id);

    void start();
    void stop();
    bool running() const noexcept { return running_.load(std::memory_order_acquire); }

private:
    using clock = std::chrono::steady_clock;

    struct Entry {
        std::shared_ptr<ReloadableResourceBase> resource;
        std::chrono::milliseconds interval;
        clock::time_point next_check;
        bool force = true;
    };

    void run();

    mutable std::mutex lock_;
    std::condition_variable wake_;
    std::unordered_map<resource_id, Entry> resources_;
    std::thread thread_;
    std::atomic_bool running_{false};
    bool stopping_ = false;
    resource_id next_id_ = 1;
};

} // namespace sx::reload
