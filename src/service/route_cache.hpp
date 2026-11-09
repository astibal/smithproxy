#pragma once

#include <chrono>
#include <cstdint>
#include <utils/lru.hpp>
#include <mutex>
#include <optional>
#include <string>

namespace sx::net {

// LRUCache owns storage, recency and eviction. This wrapper adds route-specific
// TTL and generation checks, sharing the storage mutex to make them atomic.
// Kernel lookups run without that mutex; invalidation discards in-flight results.
class RouteCache {
public:
    using Clock = std::chrono::steady_clock;
    explicit RouteCache(std::size_t capacity = 16384) : entries_(capacity) {}

    std::uint64_t invalidate() {
        std::lock_guard lock(entries_.lock());
        entries_.clear_ul();
        return ++generation_;
    }

    template<class Resolver>
    std::optional<std::uint32_t> lookup(const std::string& key, Resolver resolve,
                                        std::optional<std::uint64_t> expected = std::nullopt) const {
        std::uint64_t generation;
        {
            std::lock_guard lock(entries_.lock());
            generation = generation_;
            if(expected && *expected != generation) {
                return std::nullopt;
            }
            const auto entry = entries_.get_ul(key);
            if(entry && entry->expires > Clock::now()) {
                return entry->index;
            }
            // An expired entry is never returned. It remains bounded by the LRU
            // capacity and will be replaced after resolution or cleared on invalidation.
        }

        // Cache misses can block in netlink. Preserve the observed generation,
        // but release the mutex so unrelated destinations can use cached results.
        const auto index = resolve();
        std::lock_guard lock(entries_.lock());
        // Never insert or return a route resolved across a routing-state change.
        if(generation != generation_) {
            return std::nullopt;
        }
        // put_ul handles replacement, eviction and zero-capacity caches.
        entries_.put_ul(key, Entry{index, Clock::now() + std::chrono::seconds(index ? 30 : 1)});
        return index;
    }

private:
    struct Entry {
        std::optional<std::uint32_t> index;
        Clock::time_point expires;
    };
    std::uint64_t generation_ = 0;
    mutable LRUCache<std::string, Entry> entries_;
};

} // namespace sx::net
