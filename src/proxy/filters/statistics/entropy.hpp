

#pragma once

#ifndef ENTROPY_HPP
#define ENTROPY_HPP

#include <nlohmann/json.hpp>
class buffer;

struct Entropy {
    static inline constexpr uint16_t first_bytes = 512;   // number of bytes at the beginning of "packet" always calculated in
    static inline constexpr uint16_t then_each = 5;       // after first bytes, calculate-in only each n-th byte
    static inline constexpr uint16_t then_max_count = 50; // calculate-in n-th byte only N-times


    std::array<uint64_t , 256> frequencies {0};
    uint8_t top_byte = 0;
    uint64_t top_freq = 0;
    double top_byte_ratio = 0;
    double entropy = 0.0f;

    uint64_t data_accounted = 0;

    void update(const uint8_t* data, size_t len);
    void update(buffer const& buf);

    void reset_results();
    void calculate();

    std::string to_string(unsigned int verbosity) const;
    nlohmann::json to_json() const;
};

#endif