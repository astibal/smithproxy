
#pragma once

#ifndef FLOWANALYSIS_HPP
#define FLOWANALYSIS_HPP

#include <nlohmann/json.hpp>
#include <array>
#include <optional>

#include <utils/checkpoints.hpp>
#include <vars.hpp>

class buffer;

struct FlowAnalysis {

    size_t count_all = 0; // all bytes in whole connection
    size_t count_all_left = 0; // all left bytes in whole connection
    size_t count_all_right = 0; // all right bytes in whole connection


    size_t count_left = 0;  // sum of left bytes in exchanges stored in flow history
    size_t count_right = 0; // sum of right bytes in exchanges stored in flow history

    size_t _current_index = 0;
    static inline constexpr size_t max_history = 256;

    // negative values are uploads
    std::array<long long, max_history> history;

    // millisecond exchange
    struct ClickData {
        socle::side_t side = socle::side_t::LEFT;
        size_t bytes = 0L;
    };
    MS_checkpoint<ClickData, max_history> millideltas;

    struct {
        double skew_all = 0.0f;
        double skew_history = 0.0f;
        std::array<std::optional<double>, max_history> ratios {0};
    } result {};

    void update(socle::side_t side, const uint8_t* data, size_t len);
    void update(socle::side_t side, buffer const& buf);
    void calculate();

    template<std::size_t N>
    std::array<std::optional<double>, N> ratios() const;

    std::string to_string(unsigned int level) const;
    nlohmann::json to_json() const;
};

template<std::size_t N>
inline std::array<std::optional<double>, N> FlowAnalysis::ratios() const {

    auto const &md = millideltas;

    size_t maxPositiveBytes = 0L;  // Global max for positive values
    size_t maxNegativeBytes = 0L;  // Global max for negative values (in terms of magnitude)
    std::array<std::optional<double>, N> normalizedValues = {};

    for (std::size_t i = 0; i < N; ++i) {
        auto const &item = millideltas.get_checkpoints()[i];
        if (item.data.side == socle::side_t::RIGHT) {
            maxPositiveBytes = std::max(maxPositiveBytes, item.data.bytes);
        } else {
            maxNegativeBytes = std::max(maxNegativeBytes, item.data.bytes);
        }
    }

    // ratios
    for (std::size_t i = 0; i < N and i < md.count(); ++i) {
        auto const &item = millideltas.get_checkpoints()[i];
        if (item.data.side == socle::side_t::RIGHT) {
            normalizedValues[i] = (maxPositiveBytes != 0) ? static_cast<double>(item.data.bytes) / maxPositiveBytes : 0;
        } else {
            normalizedValues[i] = (maxNegativeBytes != 0) ? -1.0f * static_cast<double>(item.data.bytes) /
                                                            maxNegativeBytes : 0;
        }
    }

    return normalizedValues;
}

#endif