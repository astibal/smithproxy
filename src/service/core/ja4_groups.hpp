#pragma once

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace sx::diagnostics {
struct ja4_client {
    std::string connection;
    std::string no_sni;
    std::vector<std::string> http;
};
// Snapshot retained state on owner workers; throws on incomplete collection.
std::vector<ja4_client> collect_ja4_clients();

struct ja4_group {
    int strength;
    std::string no_sni;
    std::string http;
    std::vector<std::size_t> members;
};

// Inverted indexes preserve direct evidence: overlapping HTTP signatures may
// put a session in several groups, but never merge unrelated signatures through
// a bridging session. Empty fingerprints are not evidence of a match.
inline std::vector<ja4_group> group_ja4_clients(std::vector<ja4_client> const& clients) {
    using key = std::pair<std::string, std::string>;
    std::map<key, std::vector<std::size_t>> buckets;
    for (std::size_t i = 0; i < clients.size(); ++i) {
        auto const& client = clients[i];
        if (!client.no_sni.empty()) buckets[{client.no_sni, {}}].push_back(i);
        std::set<std::string> unique_http(client.http.begin(), client.http.end());
        for (auto const& http : unique_http) {
            if (http.empty()) continue;
            buckets[{{}, http}].push_back(i);
            if (!client.no_sni.empty()) buckets[{client.no_sni, http}].push_back(i);
        }
    }
    std::vector<ja4_group> groups;
    for (auto& [fingerprints, members] : buckets) {
        if (members.size() < 2) continue;
        const bool client_match = !fingerprints.first.empty();
        const bool http_match = !fingerprints.second.empty();
        const int strength = client_match && http_match ? 3 : client_match ? 2 : 1;
        groups.push_back({strength, fingerprints.first, fingerprints.second, std::move(members)});
    }
    std::sort(groups.begin(), groups.end(), [](auto const& a, auto const& b) {
        if (a.strength != b.strength) return a.strength > b.strength;
        if (a.members.size() != b.members.size()) return a.members.size() > b.members.size();
        if (a.no_sni != b.no_sni) return a.no_sni < b.no_sni;
        return a.http < b.http;
    });
    return groups;
}
} // namespace sx::diagnostics
