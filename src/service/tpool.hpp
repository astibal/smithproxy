/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#pragma once

#ifndef TPOOL_HPP
#define TPOOL_HPP

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>

#include <socle/common/stringformat.hpp>
#include <socle/common/convert.hpp>

/*
 * Class to provide utility thread pool, running miscellaneous, short-lived tasks.
 * Example of the use (partly a pseudocode):
   ```cpp
        int repeats = 10;

        pool.enqueue([repeats](std::atomic_bool const& stop_flag) {
            for(int i = 0; i < repeats; ++i) {
                if(stop_flag) break;

                std::cout << "Attempt " << i << "!" << std::endl;
                sleep_ms(ThreadPool::milliseconds);
            }
        });
   ```
 */

namespace sx::tp {

class PoolTask {
public:
    PoolTask() = default;
    virtual ~PoolTask() = default;
    virtual void execute(std::atomic_bool const& stop_flag) = 0;
    virtual std::string info_short() const = 0;
    virtual std::string info_long() const = 0;
    virtual std::string info_detailed() const { return info_long(); };
    virtual void set_log_buffer(std::stringstream& ss) { /* this override is not mandatory */ };
};


class ThreadPool {
private:

    // calling functions taking reference
    std::vector<std::thread> workers_;
    std::deque<std::unique_ptr<PoolTask>> tasks_;

    struct worker_tasks_t {
        // each thread worker will collect info from tasks
        std::vector<std::string> info_short;
        std::vector<std::string> info_long;
        std::vector<std::string> info_details;
        // log buffer is shared with the task, so they can log into
        std::vector<std::stringstream> log_buffer;
        std::vector<bool> is_finished;

        void init(size_t threads) {
            // initialize currently processed tasks info
            for (size_t i = 0; i < threads; ++i) {
                info_short.emplace_back();
                info_long.emplace_back();
                info_details.emplace_back();
                log_buffer.emplace_back();
                is_finished.emplace_back(false);
            }
        };

        void clear(size_t thread_idx) {
            info_short[thread_idx].clear();
            info_long[thread_idx].clear();
            info_details[thread_idx].clear();

            log_buffer[thread_idx].clear();
            log_buffer[thread_idx].str({});

            is_finished[thread_idx] = false;
        };
    };
    worker_tasks_t worker_tasks {};

    mutable std::mutex lock_;
    std::condition_variable cv_;

    std::atomic_bool stop_ = false;
    std::atomic_uint active = 0;

    struct stats_t {
        std::atomic_uint64_t total_executed = 0;
        std::atomic_uint64_t total_finished = 0;

        std::atomic_uint std_except = 0;
        std::atomic_uint unk_except = 0;
    };
    stats_t stats_;

public:
    static inline std::atomic_bool collect_tasks_info = false;

    stats_t const &stats() const { return stats_; }
    worker_tasks_t const& get_worker_tasks() const { return worker_tasks; }

    // advice/recommendation for longer task to schedule their loops to check stop flag (if any)
    static constexpr unsigned long milliseconds = 100;

    explicit ThreadPool(size_t threads) {

        for (size_t thread_idx = 0; thread_idx < threads; ++thread_idx) {
            worker_tasks.init(threads);

            workers_.emplace_back([this, thread_idx] {
                while (true) {
                    std::unique_ptr<PoolTask> task;
                    {
                        auto lc_ = std::unique_lock(lock_);
                        this->cv_.wait(lc_, [this] {
                            return this->stop_ || !this->tasks_.empty();
                        });

                        // regardless of enqueued tasks, return if stop_ is set!
                        if (this->stop_) return;

                        if (tasks_.empty()) {
                            continue;
                        }
                        task = std::move(this->tasks_.front());
                        this->tasks_.pop_front();

                        if(collect_tasks_info) {
                            worker_tasks.clear(thread_idx);
                            worker_tasks.info_short[thread_idx] = task->info_short();
                            worker_tasks.info_long[thread_idx] = task->info_long();
                            worker_tasks.info_details[thread_idx] = task->info_detailed();
                            task->set_log_buffer(worker_tasks.log_buffer[thread_idx]);
                        }
                    }

                    this->active++;
                    try {

                        stats_.total_executed++;
                        // RUN THE TASK
                        task->execute(this->stop_);
                        stats_.total_finished++;

                    }
                    catch (std::exception const &) {
                        this->stats_.std_except++;
                    }
                    catch (...) {
                        this->stats_.unk_except++;
                    }
                    this->active--;
                    {
                        auto lc_ = std::scoped_lock(lock_);
                        worker_tasks.is_finished[thread_idx] = true;
                    }
                }
            });

            pthread_setname_np(workers_.back().native_handle(), string_format("sxy_tpo_%d", thread_idx).c_str());
        }
    }

    size_t worker_count() const {
        auto lc_ = std::unique_lock(lock_);
        return workers_.size();
    }

    size_t tasks_size() const {
        auto lc_ = std::unique_lock(lock_);
        return tasks_.size();
    }

    std::mutex& get_lock() const {
        return lock_;
    }

    auto const& get_tasks() const {
        return tasks_;
    }

    auto const& get_workers() const {
        return workers_;
    }


    size_t tasks_running() const {
        return active;
    }

    void stop() { stop_ = true; }
    void start() { stop_ = false; }
    [[nodiscard]] bool is_active() const { return (! stop_); }
    [[nodiscard]] bool is_stopping() const { return stop_; }

    void ready(bool b) { stop_ = b ; }


    ssize_t enqueue(std::unique_ptr<PoolTask>&& f) {
        ssize_t ret = 0;
        {
            auto lc_ = std::unique_lock(lock_);
            if (stop_) {
                return -1;
            }
            tasks_.emplace_back(std::move(f));
            ret = socle::raw::to_signed_cast<ssize_t>(tasks_.size()).value_or(-1);
        }
        cv_.notify_one();
        return ret;
    }

    ~ThreadPool() {
        stop_ = true;

        cv_.notify_all();
        for (std::thread& worker : workers_) {
            if(worker.joinable())
                worker.join();
        }
    }

    class instance {
        static inline std::unique_ptr<ThreadPool> pool;
        static inline std::once_flag once_flag;
        static inline size_t POOL_MUL = 2;
        static inline size_t POOL_SIZE = POOL_MUL * std::thread::hardware_concurrency();
    public:
        static ThreadPool& get() {
            std::call_once(once_flag, []() {
                pool = std::make_unique<ThreadPool>(POOL_SIZE);
            });

            if(not pool) {
                throw std::runtime_error("thread pool not running!");
            }

            return *pool;
        }
    };
};

}


#endif // TPOOL_HPP