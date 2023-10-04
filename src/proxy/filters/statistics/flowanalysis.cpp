
#include <proxy/filters/statistics/flowanalysis.hpp>
#include <buffer.hpp>
#include <vars.hpp>

void FlowAnalysis::update(socle::side_t side, buffer const& buf) {
    update(side, buf.data(), buf.size());
}

void FlowAnalysis::update(socle::side_t side, const uint8_t *data, size_t len) {

    count_all += len;
    side == socle::side_t::LEFT ? count_all_left+=len : count_all_right+=len;

    auto slen = static_cast<int>(len);

    if(_current_index < max_history) {

        side == socle::side_t::LEFT ? count_left+=len : count_right+=len;
        millideltas.click({ side, len } );

        ++_current_index;
    }
}

void FlowAnalysis::calculate() {

    auto calculate_skew = [](auto left, auto right) {
        auto total = static_cast<double>(left+right);
        auto l = static_cast<long long>(left);
        auto r = static_cast<long long>(right);
        return static_cast<double>(r - l)/total;
    };

    result.skew_all = calculate_skew(count_all_left, count_all_right);
    result.skew_history = calculate_skew(count_left, count_right);
    result.ratios = ratios<max_history>();
    result.aggregated_ratios = aggregate<max_history>(1000); // aggregate to 1000ms
}


std::string FlowAnalysis::to_string(unsigned int level) const {

    std::stringstream ss;
    ss << "skew: " << result.skew_history << " skew_all: " << result.skew_all;
    if(level > iINF) {
        auto resampled = ratios<max_history>();

        ss << "\r\n    deltas: ";
        for (size_t i = 0; i < millideltas.get_checkpoints().size() and i < millideltas.count(); ++i) {
            auto const &delta = millideltas.get_checkpoints()[i];
            double ratio = 0.0f;
            if(i < resampled.size()) ratio = resampled[i].value_or(0.0f);

            ss << "(" << socle::from_side(delta.data.side) << ", " << delta.delta << "ms, " << delta.data.bytes << "B, ";
            ss << ratio << "r )";
        }
    }
    ss << "\r\n    aggregate ratios: ";
    for(auto const& agg: result.aggregated_ratios) {
        ss << "[ " << agg.first << "s, " << agg.second.aggregated_up_bytes << "/" << agg.second.aggregated_up_ratio << "upB/R ";
        ss << agg.second.aggregated_down_bytes << "/" << agg.second.aggregated_down_ratio << "downB/R ] ";
    }
    return ss.str();
}

nlohmann::json FlowAnalysis::to_json() const {

    auto ret = nlohmann::json();

    ret["skew"] = result.skew_history;
    ret["skew_all"]  = result.skew_all;


    auto resampled = ratios<max_history>();
    for (size_t i = 0; i < millideltas.get_checkpoints().size() and i < millideltas.count(); ++i) {
        auto const &delta = millideltas.get_checkpoints()[i];

        double ratio = 0.0f;
        if(i < resampled.size()) {
            ratio = resampled[i].value_or(0.0f);
        }

        char side[] = { (char) socle::from_side(delta.data.side), 0x0 };

        ret["deltas"].push_back({
                                        { "side", side }, {"delta", delta.delta }, { "bytes", delta.data.bytes },
                                        { "ratio", ratio }
                                });
    }

    for(auto const& agg: result.aggregated_ratios) {
        ret["aggregate_rates"].push_back({
                     { "interval_index", agg.first }, { "aggBU", agg.second.aggregated_up_bytes }, { "aggRU", agg.second.aggregated_up_ratio },
                     { "aggBD", agg.second.aggregated_down_bytes }, { "aggRD", agg.second.aggregated_down_ratio },
        });
    }
    return ret;
}
