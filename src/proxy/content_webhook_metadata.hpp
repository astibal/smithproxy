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
        std::vector<std::string> const& known_encodings,
        engine::http::PayloadAnnotations const& annotations = {}) {
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

    auto serialized_annotations = nlohmann::json::array();
    for(auto const& annotation : annotations) {
        auto entry = nlohmann::json::array({annotation.start, annotation.end,
                                            annotation.kind});
        if(!annotation.attributes.empty()) {
            auto attributes = nlohmann::json::object();
            for(auto const& [key, value] : annotation.attributes) {
                std::visit([&](auto const& item) { attributes[key] = item; }, value);
            }
            entry.push_back(std::move(attributes));
        }
        serialized_annotations.push_back(std::move(entry));
    }

    return {
        {"L7_payload_start", std::move(starts)},
        {"L7_payload_end", std::move(ends)},
        {"L7_encoding", std::move(encodings)},
        {"content_annotations", std::move(serialized_annotations)}
    };
}

} // namespace sx::proxy
