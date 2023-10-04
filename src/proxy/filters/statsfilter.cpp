
#include <proxy/filters/statsfilter.hpp>

void StatsFilter::update(socle::side_t side, buffer const& buf) {
    _deb("stats[%c]: statistics filter updated with %d bytes", socle::from_side(side), buf.size());

    // update entropy statistics
    side == side_t::LEFT ?
    shannon_entropy.left_scores.update(buf) : shannon_entropy.right_scores.update(buf);

    // update flow analysis statistics
    exchanges.update(side, buf);

    // update application information
    if(parent() and parent()->first_left()) {
        auto const* mh = parent()->first_left();
        auto app = mh->engine_ctx.application_data;

        if(app) {
            auto protocol = app->protocol();
            if(protocol != _connection_protocol_last) {
                _connection_protocol_last = protocol;

                if(not connection_protocol.empty())
                    connection_protocol += "+";
                connection_protocol += protocol;
            }
        }
    }
    new_data = true;
}

void StatsFilter::proxy(baseHostCX *from, baseHostCX *to, socle::side_t side, bool redirected) {
    update(side, from->to_read());
}

void StatsFilter::recalculate() {
    new_data = true;
    finish();
}

void StatsFilter::finish() {

    if(new_data) {
        shannon_entropy.left_scores.calculate();
        shannon_entropy.right_scores.calculate();
        exchanges.calculate();
        new_data = false;
    }
}


void StatsFilter::update_states() {
    finish(); // recalculate
}

std::string StatsFilter::to_string(int verbosity) const {
    std::stringstream ss;
    ss << "\r\n === Stats-Filter: ===";

    // calculate everything
    auto LE = shannon_entropy.left_scores.entropy;
    auto RE = shannon_entropy.right_scores.entropy;

    // prepare values
    auto LE_D = shannon_entropy.left_scores.top_byte;
    auto RE_D = shannon_entropy.right_scores.top_byte;

    auto LE_DR = shannon_entropy.left_scores.top_byte_ratio;
    auto RE_DR = shannon_entropy.right_scores.top_byte_ratio;

    auto connection_str = connection_label;
    if(not connection_protocol.empty()) {
        connection_str += "/" + connection_protocol;
    }

    ss << string_format("\r\n  %s: entropy: LE: %f, RE %f", connection_str.c_str(), LE, RE);
    if(LE < 3.0f or RE < 3.0f) {
        ss << string_format("\r\n    LOW entropy: LE: %f, RE %f", connection_str.c_str(), LE, RE);
        ss << string_format("\r\n      l-dom byte: dec(%d), ratio(%.3f)", LE_D, LE_DR);
        ss << string_format("\r\n      r-dom byte: dec(%d), ratio(%.3f)", RE_D, RE_DR);
    }

    if(verbosity >= DEB) {
        ss << "\r\nEntropy left:";
        auto left_freq_str = shannon_entropy.left_scores.to_string(verbosity);
        ss << string_format("\r\n    %s", left_freq_str.c_str());
        ss << "\r\nEntropy right:";
        auto right_freq_str = shannon_entropy.right_scores.to_string(verbosity);
        ss << string_format("\r\n    %s", right_freq_str.c_str());
    }

    ss << "\r\n";
    auto ex_stats = exchanges.to_string(verbosity);
    ss << string_format("\r\nExchange statistics:");
    ss << string_format("\r\n     %s", ex_stats.c_str());

    ss << "\r\n === Stats-Filter: ===";
    return ss.str();
}

nlohmann::json StatsFilter::to_json() const {

    auto json_en_l = shannon_entropy.left_scores.to_json();
    auto json_en_r = shannon_entropy.right_scores.to_json();
    auto json_ex = exchanges.to_json();

    auto json_all = nlohmann::json();
    json_all["entropy"] = { { "left", json_en_l }, { "right", json_en_r } };
    json_all["flow"] = json_ex;

    return json_all;
}

StatsFilter::~StatsFilter() {
    // there used to be useful code here
}


