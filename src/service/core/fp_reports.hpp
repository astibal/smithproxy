#pragma once

#include <service/core/ja4_groups.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <tuple>
#include <proxy/fingerprint_history.hpp>

namespace sx::diagnostics {
using fingerprint_key = std::pair<std::string, std::string>;

inline std::set<fingerprint_key> session_fingerprints(ja4_client const& client) {
    std::set<fingerprint_key> values;
    auto add = [&](std::string const& type, std::string const& value) {
        if (!value.empty()) values.emplace(type, value);
    };
    add("JA4", client.standard);
    add("JA4 no-SNI", client.no_sni);
    add("JA4S", client.server);
    add("L7 signature [" + client.signature_group + "]", client.signature);
    for (auto const& value : client.http) add("JA4H", value);
    return values;
}

// Both frontends consume this report verbatim. Counts are sessions, not HTTP
// requests: repeated fingerprints within a session contribute only once.
inline nlohmann::json fingerprint_report(std::vector<ja4_client> clients,
                                        std::string const& view,
                                        std::string const& source = {}) {
    const bool profile = view == "client-profile";
    const bool rare = view == "rare";
    const bool signatures = view == "signature-matches";
    if (!profile && !rare && !signatures) throw std::invalid_argument("Unknown fingerprint view");
    if (!profile && !source.empty()) throw std::invalid_argument("Source filter is only supported by client-profile");
    std::sort(clients.begin(), clients.end(), [](auto const& a, auto const& b) {
        return std::tie(a.source, a.connection) < std::tie(b.source, b.connection);
    });
    nlohmann::json result = {{"complete", true}, {"view", view},
        {"scope", "active sessions"}, {"source", source},
        {"groups", nlohmann::json::array()}};
    std::map<fingerprint_key, std::vector<std::size_t>> buckets;
    std::size_t considered = 0;
    for (std::size_t i = 0; i < clients.size(); ++i) {
        auto const& client = clients[i];
        if (!source.empty() && client.source != source) continue;
        ++considered;
        if (profile) buckets[{"source", client.source}].push_back(i);
        else if (rare) {
            for (auto const& key : session_fingerprints(client)) buckets[key].push_back(i);
        } else if (!client.signature.empty()) {
            buckets[{client.signature_group, client.signature}].push_back(i);
        }
    }
    result["sessions_considered"] = considered;
    result["note"] = rare ? "Rarity is not evidence of malicious activity. Counts are sessions."
        : profile ? "A source address may represent multiple tools or clients."
        : "Exact retained L7 signature and signature-group matches.";
    for (auto const& [key, members] : buckets) {
        if (signatures && members.size() < 2) continue;
        nlohmann::json group = {{"kind", key.first}, {"value", key.second},
            {"session_count", members.size()}, {"sessions", nlohmann::json::array()},
            {"fingerprints", nlohmann::json::array()}};
        std::map<fingerprint_key, std::size_t> counts;
        std::set<std::string> sources;
        for (auto index : members) {
            auto const& client = clients[index];
            sources.insert(client.source);
            group["sessions"].push_back({{"source", client.source}, {"connection", client.connection}});
            if (profile) for (auto const& fp : session_fingerprints(client)) ++counts[fp];
        }
        group["source_count"] = sources.size();
        for (auto const& [fp, count] : counts) {
            group["fingerprints"].push_back({{"type", fp.first}, {"value", fp.second}, {"session_count", count}});
        }
        result["groups"].push_back(std::move(group));
    }
    if (!profile) {
        auto& groups = result["groups"];
        std::stable_sort(groups.begin(), groups.end(), [rare](auto const& a, auto const& b) {
            return rare ? a.at("session_count") < b.at("session_count")
                        : a.at("session_count") > b.at("session_count");
        });
    }
    return result;
}

// Aggregate counts, not reconstructed sessions. Keep only a small deterministic
// sample of source addresses per fingerprint; counts still cover every source.
class neighbor_fingerprint_report {
    struct aggregate {
        std::uint64_t sessions = 0;
        std::size_t sources = 0;
        std::set<std::string> examples;
    };
    std::map<fingerprint_key, aggregate> counts_;
    bool rare_;
    std::size_t scanned_ = 0;
    std::uint64_t evicted_ = 0;
public:
    explicit neighbor_fingerprint_report(bool rare) : rare_(rare) {}

    void observe(std::string const& source, FingerprintHistory const& history) {
        ++scanned_;
        FingerprintHistory::add_saturated(evicted_, history.evicted_observations);
        for (auto const& [key, entry] : history.entries) {
            const bool signature = key.first.rfind("L7 signature [", 0) == 0;
            if (!rare_ && !signature) continue;
            // Fail explicitly instead of publishing an incorrect partial ranking.
            const bool new_key = counts_.find(key) == counts_.end();
            if (new_key && counts_.size() >= 100000) {
                throw std::runtime_error("Neighbor report exceeds 100000 distinct fingerprints; no partial ranking returned");
            }
            auto& count = counts_[key];
            FingerprintHistory::add_saturated(count.sessions, entry.sessions);
            ++count.sources;
            count.examples.insert(source);
            if (count.examples.size() > 10) count.examples.erase(std::prev(count.examples.end()));
        }
    }

    nlohmann::json finish() const {
        using item = decltype(counts_)::value_type;
        std::vector<item const*> ranked;
        for (auto const& item : counts_) {
            // Historical signature matches require distinct source profiles.
            if (!rare_ && item.second.sources < 2) continue;
            ranked.push_back(&item);
        }
        const auto total = ranked.size();
        const auto shown = std::min<std::size_t>(100, total);
        std::partial_sort(ranked.begin(), ranked.begin() + shown, ranked.end(), [this](auto a, auto b) {
            if (a->second.sessions != b->second.sessions)
                return rare_ ? a->second.sessions < b->second.sessions : a->second.sessions > b->second.sessions;
            return a->first < b->first;
        });
        auto groups = nlohmann::json::array();
        for (std::size_t i = 0; i < shown; ++i) {
            auto const& [key, count] = *ranked[i];
            groups.push_back({{"kind", key.first}, {"value", key.second},
                {"completed_sessions", count.sessions}, {"source_count", count.sources},
                {"source_examples", count.examples}, {"sources_truncated", count.sources > count.examples.size()}});
        }
        return {{"groups", std::move(groups)}, {"groups_total", total}, {"limit", 100},
            {"truncated", shown < total}, {"neighbors_scanned", scanned_},
            {"evicted_observations", evicted_}, {"consistency", "live scan; retained history only"}};
    }
};

// Historical aggregates are attached separately, never counted as live sessions.
nlohmann::json collect_fingerprint_report(std::string const& view, std::string const& source = {},
                                        std::string const& scope = "active");
} // namespace sx::diagnostics
