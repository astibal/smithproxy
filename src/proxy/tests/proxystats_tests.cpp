#include <gtest/gtest.h>

#include <proxystats.hpp>

#include <thread>
#include <vector>

TEST(ProxyStats, TracksCumulativeAndActiveSessions) {
    ProxyStats stats;

    stats.count_session_opened();
    stats.count_session_opened();
    stats.count_session_closed();

    EXPECT_EQ(stats.sessions_total(), 2);
    EXPECT_EQ(stats.sessions_active(), 1);
}

TEST(ProxyStats, AccumulatesBytesAcrossThreads) {
    ProxyStats stats;
    constexpr std::uint64_t iterations = 10000;
    constexpr std::size_t thread_count = 4;
    std::vector<std::thread> threads;

    for(std::size_t i = 0; i < thread_count; ++i) {
        threads.emplace_back([&stats] {
            for(std::uint64_t j = 0; j < iterations; ++j) {
                stats.count_bytes_up(3);
                stats.count_bytes_down(7);
            }
        });
    }
    for(auto& thread : threads) thread.join();

    EXPECT_EQ(stats.bytes_up(), thread_count * iterations * 3);
    EXPECT_EQ(stats.bytes_down(), thread_count * iterations * 7);
}
