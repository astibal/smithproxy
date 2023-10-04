#include <proxy/filters/statistics/entropy.hpp>

#include <buffer.hpp>
#include <log/logger.hpp>


void Entropy::update(const uint8_t *data, size_t len) {

    // safeguard invalid inputs
    if(not data or len == 0) { return; }

    size_t then_counter = 0;

    for (size_t i = 0; i < len; ++i) {
        if(i < first_bytes) {
            frequencies[data[i]]++;
            ++data_accounted;
        }
        else if (i % then_each == 0 and then_counter < then_max_count) {
            ++then_counter;
            frequencies[data[i]]++;
            ++data_accounted;
        }
        else {
            break;
        }
    }
}

std::string Entropy::to_string(unsigned int verbosity) const {
    std::stringstream ss;

    ss << " entropy: " << entropy;
    ss << ", top_byte: " << int(top_byte);
    ss << ", top_byte_fr: " << top_freq;
    ss << ", top_byte_ra: " << top_byte_ratio;
    ss << ", bytes_acct: " << data_accounted;

    if(verbosity > iINF) {
        ss << "\r\n frequencies: ";
        for (size_t i = 0; i < frequencies.size(); ++i) {
            auto val = frequencies[i];
            if (val)
                ss << "[" << i << "]=" << val << " ";
        }
    }
    return ss.str();
}

nlohmann::json Entropy::to_json(int verbosity) const {
    auto ret = nlohmann::json();
    ret["entropy"] = entropy;
    ret["top_byte"] = top_byte;
    ret["top_byte_frequency"] = top_freq;
    ret["top_byte_ratio"] = top_byte_ratio;
    ret["bytes_accounted"] = data_accounted;

    if(verbosity > iINF) {
        for (size_t i = 0; i < frequencies.size(); ++i) {
            auto val = frequencies[i];
            if (val > 0)
                ret["byte_counts"].push_back({i, val});
        }
    }
    return ret;
}

void Entropy::reset_results() {
    // all other variables are re-counted, or have no impact on consecutive calls
    entropy = 0.0f;
}

void Entropy::calculate() {

    reset_results();

    for (size_t i = 0; i < frequencies.size(); ++i) {
        auto freq = frequencies[i];
        if (freq > 0) {

            if (freq > top_freq) {
                top_freq = freq;
                top_byte = static_cast<uint8_t>(i); // this is safe, size is always 256 to count byte values
            }

            double probability = static_cast<double>(freq) / data_accounted;
            entropy -= probability * std::log2(probability);
        }
    }

    top_byte_ratio = static_cast<double>(top_freq) / data_accounted;
}


void Entropy::update(buffer const& buf) {
    update(buf.data(), buf.size());
}
