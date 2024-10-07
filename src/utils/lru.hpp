#include <iostream>
#include <unordered_map>
#include <list>
#include <optional>
#include <mutex>

template<typename Key, typename Value>
class LRUCache {
private:
    size_t capacity_;
    std::unordered_map<Key, std::pair<Value, typename std::list<Key>::iterator>> cache_;
    std::list<Key> lruList;

    mutable std::mutex lock_;
public:
    explicit LRUCache(size_t cap) : capacity_(cap) {}
    std::mutex& lock() const { return lock_; }

    auto const& get_map_ul() const {
        return cache_;
    }

    std::optional<Value> get(Key const& key) {
        auto lc_ = std::scoped_lock(lock_);
        return get_ul(key);
    }

    void put(const Key& key, Value const& value) {
        auto lc_ = std::scoped_lock(lock_);
        put_ul(key, value);
    }

    std::optional<Value> get_ul(Key const& key) {

        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return std::nullopt;
        }
        lruList.erase(it->second.second);
        lruList.push_front(key);
        it->second.second = lruList.begin();
        return it->second.first;
    }

    size_t capacity_ul() const {
        return capacity_;
    }

    size_t capacity() const {
        auto lc_ = std::scoped_lock(lock_);
        return capacity_ul();
    }

    void set_capacity(size_t new_capacity) {
        auto lc_ = std::scoped_lock(lock_);
        set_capacity_ul(new_capacity);
    }

    void set_capacity_ul(size_t new_capacity) {
        capacity_ = new_capacity;
        cleanup_ul();
    }

    void cleanup_ul() {
        while(cache_.size() >= capacity_) {
            if(cache_.size() > 0L) {
                Key oldestKey = lruList.back();
                lruList.pop_back();
                cache_.erase(oldestKey);
            }
            else {
                break;
            }
        }
    }

    void put_ul(const Key& key, Value const& value) {

        cleanup_ul();

        if (auto it = cache_.find(key); it != cache_.end()) {
            lruList.erase(it->second.second);
            cache_.erase(it);
        }

        lruList.push_front(key);
        cache_[key] = {value, lruList.begin()};
    }

    std::string to_string(int verbosity) const {
        auto lc_ = std::scoped_lock(lock_);

        std::stringstream ss;
        for (auto& pair : cache_) {
            ss << pair.first << " : " << pair.second.first << std::endl;
        }

        return ss.str();
    }

    void clear_ul() {
        cache_.clear();
        lruList.clear();
    }

    void clear() {
        auto lc_ = std::scoped_lock(lock_);
        clear_ul();
    }
};