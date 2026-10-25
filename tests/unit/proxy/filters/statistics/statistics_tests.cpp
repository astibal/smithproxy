#include <gtest/gtest.h>

#include <proxy/filters/statistics/entropy.hpp>
#include <proxy/filters/statistics/flowanalysis.hpp>

#include <buffer.hpp>

#include <array>
#include <cmath>
#include <vector>

namespace {

TEST(EntropyStatistics, IgnoresEmptyInputAndSamplesPastInitialWindow) {
    Entropy entropy;
    entropy.update(nullptr, 100);
    entropy.update(nullptr, 0);
    EXPECT_EQ(entropy.data_accounted, 0U);

    std::vector<std::uint8_t> data(2000);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>(i);
    }
    entropy.update(data.data(), data.size());

    EXPECT_EQ(entropy.data_accounted,
              Entropy::first_bytes + Entropy::then_max_count);
    EXPECT_GT(entropy.frequencies[data[515]], 0U);
    EXPECT_EQ(entropy.frequencies[data[513]], 2U); // indices 1 and 257 only
}

TEST(EntropyStatistics, CalculatesKnownDistributionsAndSerializesDetails) {
    Entropy entropy;
    const std::array<std::uint8_t, 4> data{0, 0, 1, 1};
    entropy.update(data.data(), data.size());
    entropy.calculate();

    EXPECT_NEAR(entropy.entropy, 1.0, 1e-12);
    EXPECT_EQ(entropy.top_freq, 2U);
    EXPECT_NEAR(entropy.top_byte_ratio, 0.5, 1e-12);
    EXPECT_NE(entropy.to_string(iDEB).find("[0]=2"), std::string::npos);

    const auto json = entropy.to_json(iDEB);
    EXPECT_EQ(json.at("bytes_accounted"), 4);
    EXPECT_TRUE(json.contains("byte_counts"));

    Entropy empty;
    empty.calculate();
    EXPECT_EQ(empty.entropy, 0.0);
}

TEST(FlowAnalysisStatistics, TracksBothDirectionsAndCapsHistory) {
    FlowAnalysis flow;
    buffer left("abc", 3);
    buffer right("12345", 5);
    buffer empty;

    flow.update(socle::side_t::LEFT, empty);
    EXPECT_EQ(flow._current_index, 0U);

    flow.update(socle::side_t::LEFT, left);
    flow.update(socle::side_t::RIGHT, right);
    for (std::size_t i = 2; i < FlowAnalysis::max_history + 10; ++i) {
        flow.update(socle::side_t::LEFT, left);
    }
    flow.calculate();

    EXPECT_EQ(flow._current_index, FlowAnalysis::max_history);
    EXPECT_EQ(flow.millideltas.count(), FlowAnalysis::max_history);
    EXPECT_EQ(flow.count_all_left, 3U * (FlowAnalysis::max_history + 9));
    EXPECT_EQ(flow.count_all_right, 5U);
    EXPECT_LT(flow.result.skew_all, 0.0);
    EXPECT_LT(flow.result.skew_history, 0.0);
    ASSERT_TRUE(flow.result.ratios[0].has_value());
    ASSERT_TRUE(flow.result.ratios[1].has_value());
    EXPECT_DOUBLE_EQ(*flow.result.ratios[0], -1.0);
    EXPECT_DOUBLE_EQ(*flow.result.ratios[1], 1.0);
}

TEST(FlowAnalysisStatistics, AggregatesAndSerializesWithoutDividingByZero) {
    FlowAnalysis flow;
    const std::uint8_t byte = 0;
    flow.update(socle::side_t::LEFT, &byte, 10);
    flow.update(socle::side_t::RIGHT, &byte, 20);
    flow.calculate();

    const auto buckets = flow.aggregate<FlowAnalysis::max_history>(1000);
    ASSERT_EQ(buckets.size(), 1U);
    EXPECT_EQ(buckets.begin()->second.aggregated_up_bytes, 10U);
    EXPECT_EQ(buckets.begin()->second.aggregated_down_bytes, 20U);
    EXPECT_THROW((flow.aggregate<FlowAnalysis::max_history>(0)), std::invalid_argument);

    EXPECT_NE(flow.to_string(iDEB).find("aggregate ratios"), std::string::npos);
    const auto json = flow.to_json(iDEB);
    EXPECT_TRUE(json.contains("deltas"));
    EXPECT_TRUE(json.contains("aggregate_rates"));
}

} // namespace
