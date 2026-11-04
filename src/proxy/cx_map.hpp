#pragma once

#include <utility>
#include <vector>

namespace sx::proxy {

// Most proxies track one client and one upstream context. Keep those entries
// together; less common multi-context proxies can grow beyond the reservation.
template<typename Key, typename T>
struct CxMap {
    CxMap() {

        entries_.reserve(2);
    }

    T& get_or_create(Key cx) {

        for(auto& [context, value] : entries_) {
            if(context == cx) {
                return value;
            }
        }

        entries_.emplace_back(cx, T{});
        return entries_.back().second;
    }

    void erase(Key cx) {

        for(auto entry = entries_.begin(); entry != entries_.end(); ++entry) {
            if(entry->first == cx) {
                entries_.erase(entry);
                return;
            }
        }
    }

    void clear() {

        entries_.clear();
    }

private:
    // References are only valid until an insertion, erase or clear.
    std::vector<std::pair<Key, T>> entries_;
};

} // namespace sx::proxy
