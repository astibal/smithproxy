#include <gtest/gtest.h>

#include <service/http/webhooks.hpp>

TEST(WebhookStats, ErrorBurstRequiresConfiguredCountWithinWindow) {
    sx::http::webhooks::timestampq errors(3, 10);
    const auto now = time(nullptr);

    errors.q = {now, now - 1};
    EXPECT_FALSE(errors.triggered());

    errors.q = {now, now - 1, now - 9};
    EXPECT_TRUE(errors.triggered());

    errors.q = {now, now - 1, now - 11};
    EXPECT_FALSE(errors.triggered());
}

TEST(WebhookStats, SuccessfulUpdatesRefreshEntryLifetime) {
    sx::http::webhooks::url_stats stats;
    stats.update_incr(false);

    EXPECT_EQ(stats.counter_total(), 1U);
    EXPECT_FALSE(stats.is_error());
    EXPECT_FALSE(stats.is_expired());
}

TEST(WebhookStats, ErrorQueueRemainsBounded) {
    sx::http::webhooks::timestampq errors(3, 60);
    errors.add();
    errors.add();
    errors.add();
    errors.add();

    EXPECT_EQ(errors.q.size(), 3U);
    EXPECT_TRUE(errors.triggered());
}

TEST(UtilityThreadPool, AllocatesOneMetadataSlotPerWorker) {
    sx::tp::ThreadPool pool(3);
    auto const& info = pool.get_worker_tasks();

    EXPECT_EQ(pool.worker_count(), 3U);
    EXPECT_EQ(info.info_short.size(), 3U);
    EXPECT_EQ(info.info_long.size(), 3U);
    EXPECT_EQ(info.info_details.size(), 3U);
    EXPECT_EQ(info.log_buffer.size(), 3U);
    EXPECT_EQ(info.is_finished.size(), 3U);
    EXPECT_TRUE(std::all_of(info.is_finished.begin(), info.is_finished.end(),
                            [](bool finished) { return finished; }));
}

TEST(WebhookRefreshGate, CoalescesAcceptedResponseBursts) {
    sx::http::webhooks::refresh_gate gate(2);

    EXPECT_TRUE(gate.acquire(100));
    EXPECT_FALSE(gate.acquire(100));
    EXPECT_FALSE(gate.acquire(101));
    EXPECT_TRUE(gate.acquire(102));
}
