#pragma once

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <nlohmann/json.hpp>

// Bounded per-neighbor aggregates. Counts describe completed sessions, not
// requests. Eviction drops the least recently seen fingerprint; its lost
// session observations remain visible in the summary, never silently precise.
struct FingerprintHistory {
    using key = std::pair<std::string, std::string>;
    struct entry {
        std::uint64_t sessions = 0;
        std::time_t first_seen = 0;
        std::time_t last_seen = 0;
    };
    static constexpr std::size_t limit = 128;
    std::map<key, entry> entries;
    std::uint64_t evicted_observations = 0;

    static void add_saturated(std::uint64_t& target, std::uint64_t value) {
        target += std::min(value, std::numeric_limits<std::uint64_t>::max() - target);
    }
    void observe(std::set<key> const& fingerprints, std::time_t now) {
        for (auto const& fp : fingerprints) {
            if (fp.first.empty() || fp.second.empty() || fp.first.size() > 128 || fp.second.size() > 512) continue;
            auto found = entries.find(fp);
            if (found == entries.end()) {
                if (entries.size() >= limit) {
                    auto oldest = std::min_element(entries.begin(), entries.end(), [](auto const& a, auto const& b) {
                        return a.second.last_seen < b.second.last_seen;
                    });
                    add_saturated(evicted_observations, oldest->second.sessions);
                    entries.erase(oldest);
                }
                found = entries.emplace(fp, entry{0, now, now}).first;
            }
            add_saturated(found->second.sessions, 1);
            found->second.first_seen = std::min(found->second.first_seen, now);
            found->second.last_seen = std::max(found->second.last_seen, now);
        }
    }
    nlohmann::json to_json() const {
        auto items = nlohmann::json::array();
        for (auto const& [fp, value] : entries) {
            items.push_back({{"type", fp.first}, {"value", fp.second}, {"sessions", value.sessions},
                {"first_seen", value.first_seen}, {"last_seen", value.last_seen}});
        }
        return {{"version", 1}, {"limit", limit}, {"evicted_observations", evicted_observations},
                {"entries", std::move(items)}};
    }
    bool from_json(nlohmann::json const& json) {
        try {
            if (json.at("version") != 1 || !json.at("entries").is_array() || json.at("entries").size() > limit) return false;
            FingerprintHistory parsed;
            // Validate before unsigned conversion: malformed persisted counters
            // must not wrap negative values or silently truncate fractions.
            const auto evicted = json.value("evicted_observations", nlohmann::json(0));
            const bool unsigned_count = evicted.is_number_unsigned();
            const bool nonnegative_count = evicted.is_number_integer()
                && evicted.get<std::int64_t>() >= 0;
            if (!unsigned_count && !nonnegative_count) return false;
            parsed.evicted_observations = evicted.get<std::uint64_t>();
            for (auto const& item : json.at("entries")) {
                key fp{item.at("type").get<std::string>(), item.at("value").get<std::string>()};
                if (fp.first.empty() || fp.second.empty() || fp.first.size() > 128 || fp.second.size() > 512) return false;
                const auto count = item.at("sessions");
                if (!count.is_number_unsigned() && (!count.is_number_integer() || count.get<std::int64_t>() <= 0)) return false;
                entry value{count.get<std::uint64_t>(), item.at("first_seen").get<std::time_t>(), item.at("last_seen").get<std::time_t>()};
                if (!value.sessions || value.first_seen < 0 || value.last_seen < value.first_seen) return false;
                if (!parsed.entries.emplace(std::move(fp), value).second) return false;
            }
            *this = std::move(parsed);
            return true;
        } catch (nlohmann::json::exception const&) { return false; }
    }
};
