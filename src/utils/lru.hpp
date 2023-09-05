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

    std::mutex lock_;
public:
    explicit LRUCache(size_t cap) : capacity_(cap) {}
    std::mutex& lock() { return lock_; }

    auto const& get_map_ul() {
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

    void put_ul(const Key& key, Value const& value) {

        if (cache_.size() == capacity_) {
            Key oldestKey = lruList.back();
            lruList.pop_back();
            cache_.erase(oldestKey);
        }

        auto it = cache_.find(key);
        if (it != cache_.end()) {
            lruList.erase(it->second.second);
            cache_.erase(it);
        }

        lruList.push_front(key);
        cache_[key] = {value, lruList.begin()};
    }

    void display() {
        for (auto& pair : cache_) {
            std::cout << pair.first << " : " << pair.second.first << std::endl;
        }
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