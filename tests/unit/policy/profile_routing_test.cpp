#include <gtest/gtest.h>

#include <policy/profiles.hpp>

#include <array>
#include <thread>
#include <vector>

namespace {

TEST(ProfileRouting, RoundRobinStartsAtZeroAndEmptySetDoesNotAdvance) {
    ProfileRouting routing;

    EXPECT_EQ(routing.lb_index_rr(0), 0U);
    EXPECT_EQ(routing.lb_index_rr(3), 0U);
    EXPECT_EQ(routing.lb_index_rr(3), 1U);
    EXPECT_EQ(routing.lb_index_rr(3), 2U);
    EXPECT_EQ(routing.lb_index_rr(3), 0U);
}

TEST(ProfileRouting, LoadBalancingMethodNamesRejectTypos) {
    using method = ProfileRouting::lb_method;

    EXPECT_EQ(ProfileRouting::parse_lb_method("round-robin"), method::LB_RR);
    EXPECT_EQ(ProfileRouting::parse_lb_method("sticky-l3"), method::LB_L3);
    EXPECT_EQ(ProfileRouting::parse_lb_method("sticky-l4"), method::LB_L4);
    EXPECT_FALSE(ProfileRouting::parse_lb_method("round_robin"));
    EXPECT_FALSE(ProfileRouting::parse_lb_method("Sticky-L3"));
    EXPECT_FALSE(ProfileRouting::parse_lb_method(""));
}

TEST(ProfileRouting, SniRewriteRequiresBothSides) {
    EXPECT_TRUE(ProfileRouting::valid_sni_rewrite_pair("", ""));
    EXPECT_TRUE(ProfileRouting::valid_sni_rewrite_pair(
        "client.example", "origin.internal"));
    EXPECT_FALSE(ProfileRouting::valid_sni_rewrite_pair("client.example", ""));
    EXPECT_FALSE(ProfileRouting::valid_sni_rewrite_pair("", "origin.internal"));
}

TEST(ProfileRouting, ConcurrentRoundRobinRemainsEvenlyDistributed) {
    ProfileRouting routing;
    constexpr std::size_t workers = 8;
    constexpr std::size_t iterations = 1000;
    constexpr std::size_t choices = 4;
    std::array<std::atomic_size_t, choices> counts{};
    std::vector<std::thread> threads;

    for (std::size_t worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&] {
            for (std::size_t i = 0; i < iterations; ++i) {
                ++counts[routing.lb_index_rr(choices)];
            }
        });
    }
    for (auto& thread : threads) thread.join();

    for (auto const& count : counts) {
        EXPECT_EQ(count.load(), workers * iterations / choices);
    }
}

TEST(ProfileRouting, CandidateAccessReturnsLockedFamilySnapshots) {
    ProfileRouting routing;
    auto v4 = std::make_shared<CidrAddress>("192.0.2.1/32");
    auto v6 = std::make_shared<CidrAddress>("2001:db8::1/128");
    {
        auto l_ = std::scoped_lock(routing.lb_state.lock_);
        routing.lb_state.candidates_v4 = {v4};
        routing.lb_state.candidates_v6 = {v6};
    }

    auto snapshot4 = routing.lb_candidates(CIDR_IPV4);
    auto snapshot6 = routing.lb_candidates(CIDR_IPV6);
    ASSERT_EQ(snapshot4.size(), 1U);
    ASSERT_EQ(snapshot6.size(), 1U);
    EXPECT_EQ(snapshot4.front()->ip(), "192.0.2.1");
    EXPECT_EQ(snapshot6.front()->ip(), "2001:db8::1");

    {
        auto l_ = std::scoped_lock(routing.lb_state.lock_);
        routing.lb_state.candidates_v4.clear();
    }
    EXPECT_EQ(snapshot4.size(), 1U);
    EXPECT_TRUE(routing.lb_candidates(AF_INET).empty());
}

} // namespace
