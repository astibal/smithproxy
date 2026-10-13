#pragma once

#include <inspect/engine/http.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace sx::proxy {

// Build the exact L7 fields inserted into content-webhook info. Keeping this
// transformation pure makes the wire contract independently testable.
inline nlohmann::json l7_payload_metadata(
        engine::http::L7PayloadHints const& ranges,
        std::vector<std::string> const& known_encodings) {
    auto starts = nlohmann::json::array();
    auto ends = nlohmann::json::array();
    auto encodings = nlohmann::json::array();

    if(ranges.empty()) {
        starts.push_back(-1);
        ends.push_back(-1);
        encodings.push_back("");
    } else {
        const bool encodings_match = known_encodings.size() == ranges.size();
        for(std::size_t index = 0; index < ranges.size(); ++index) {
            starts.push_back(ranges[index].first);
            ends.push_back(ranges[index].second);
            encodings.push_back(encodings_match ? known_encodings[index] : "");
        }
    }

    return {
        {"L7_payload_start", std::move(starts)},
        {"L7_payload_end", std::move(ends)},
        {"L7_encoding", std::move(encodings)}
    };
}

} // namespace sx::proxy
