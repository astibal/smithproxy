#include <gtest/gtest.h>

#include <proxy/filters/statsfilter.hpp>

#include <tcpcom.hpp>

// The focused unit-test target deliberately does not link the full proxy
// runtime. Detached StatsFilter instances never use their parent, so this
// supplies only the unreachable link seam referenced by StatsFilter::update.
MitmHostCX* MitmProxy::first_left() const {
    return nullptr;
}

namespace {

TEST(StatsFilter, EmptyFilterHasNoUsableState) {
    StatsFilter filter(nullptr);

    EXPECT_FALSE(filter.update_states());
    EXPECT_NO_THROW(filter.proxy(nullptr, nullptr, socle::side_t::LEFT, false));
    EXPECT_EQ(filter.shannon_entropy.left_scores.data_accounted, 0U);
    EXPECT_EQ(filter.shannon_entropy.right_scores.data_accounted, 0U);
}

TEST(StatsFilter, AccountsBothDirectionsAndSerializesResults) {
    StatsFilter filter(nullptr);
    buffer left("aaaa", 4);
    buffer right("01234567", 8);

    filter.update(socle::side_t::LEFT, left);
    filter.update(socle::side_t::RIGHT, right);

    ASSERT_TRUE(filter.update_states());
    EXPECT_EQ(filter.shannon_entropy.left_scores.data_accounted, 4U);
    EXPECT_EQ(filter.shannon_entropy.right_scores.data_accounted, 8U);
    EXPECT_EQ(filter.exchanges.count_all_left, 4U);
    EXPECT_EQ(filter.exchanges.count_all_right, 8U);

    auto json = filter.to_json(iDEB);
    EXPECT_EQ(json.at("entropy").at("left").at("bytes_accounted"), 4U);
    EXPECT_EQ(json.at("entropy").at("right").at("bytes_accounted"), 8U);
    EXPECT_TRUE(json.at("flow").contains("deltas"));
    EXPECT_NE(filter.to_string(iDEB).find("LOW entropy"), std::string::npos);
}

TEST(StatsFilter, ProxyUsesTheSelectedEndpointInput) {
    StatsFilter filter(nullptr);
    baseHostCX from(new TCPCom(), -1);
    baseHostCX to(new TCPCom(), -1);
    from.to_read().assign("abc");

    filter.proxy(&from, &to, socle::side_t::RIGHT, false);
    filter.recalculate();

    EXPECT_EQ(filter.shannon_entropy.right_scores.data_accounted, 3U);
    EXPECT_EQ(filter.exchanges.count_all_right, 3U);
}

} // namespace
