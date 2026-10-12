#pragma once

#include <algorithm>
#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace sx::cli {

struct client_task {
    std::thread worker;
    std::shared_ptr<std::atomic_bool> finished;
};

inline std::size_t reap_finished_client_tasks(
        std::vector<client_task>& tasks) {
    const auto before = tasks.size();
    tasks.erase(std::remove_if(tasks.begin(), tasks.end(), [](client_task& task) {
        if(!task.finished || !task.finished->load(std::memory_order_acquire))
            return false;
        if(task.worker.joinable()) task.worker.join();
        return true;
    }), tasks.end());
    return before - tasks.size();
}

} // namespace sx::cli
