#include <gtest/gtest.h>

#include <service/cfgapi/cfg_write_gate.hpp>

#include <chrono>
#include <future>
#include <mutex>

using namespace std::chrono_literals;

TEST(CfgWriteGate, OrdinaryWriterHoldsTheConfigMutex) {
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;
    auto guard = gate.enter(config_mutex);
    ASSERT_TRUE(guard);

    auto locked_elsewhere = std::async(std::launch::async, [&config_mutex] {
        const bool locked = config_mutex.try_lock();
        if(locked) config_mutex.unlock();
        return locked;
    });

    EXPECT_FALSE(locked_elsewhere.get());
}

TEST(CfgWriteGate, ActiveLeaseBlocksOrdinaryWriter) {
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    auto grant = gate.acquire("revision-1", "gui", [] { return "revision-1"; });
    ASSERT_TRUE(grant);

    EXPECT_FALSE(gate.enter(config_mutex));
}

TEST(CfgWriteGate, LeaseHolderRequiresMatchingTokenAndRevision) {
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    ASSERT_TRUE(gate.acquire("revision-1", "gui", [] { return "revision-1"; }));

    EXPECT_FALSE(gate.enter(config_mutex, "wrong-token", "revision-1"));
    EXPECT_FALSE(gate.enter(config_mutex, "lease-token", "revision-2"));
    EXPECT_TRUE(gate.enter(config_mutex, "lease-token", "revision-1"));
}

TEST(CfgWriteGate, RejectsLeaseForStaleBaseRevision) {
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });

    EXPECT_FALSE(gate.acquire("revision-1", "gui", [] { return "revision-2"; }));
    EXPECT_FALSE(gate.active());
}

TEST(CfgWriteGate, ReleaseAllowsOrdinaryWriter) {
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    ASSERT_TRUE(gate.acquire("revision-1", "gui", [] { return "revision-1"; }));

    EXPECT_TRUE(gate.release("lease-token"));
    EXPECT_TRUE(gate.enter(config_mutex));
}

TEST(CfgWriteGate, WaitingWriterEntersAfterLeaseRelease) {
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    ASSERT_TRUE(gate.acquire("revision-1", "gui", [] { return "revision-1"; }));

    auto waiting_writer = std::async(std::launch::async, [&gate, &config_mutex] {
        return gate.enter_wait(config_mutex, 10ms, [](auto) { return true; }).has_value();
    });
    EXPECT_EQ(waiting_writer.wait_for(20ms), std::future_status::timeout);

    EXPECT_TRUE(gate.release("lease-token"));
    EXPECT_TRUE(waiting_writer.get());
}

TEST(CfgWriteGate, WaitingWriterTimesOutWhileLeaseRemainsActive) {
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    ASSERT_TRUE(gate.acquire("revision-1", "gui", [] { return "revision-1"; }));

    std::chrono::milliseconds observed {};
    EXPECT_FALSE(gate.enter_wait(config_mutex, 10ms, [&observed](auto elapsed) {
        observed = elapsed;
        return elapsed < 20ms;
    }));
    EXPECT_GE(observed, 20ms);
}

TEST(CfgWriteGate, WaitingWriterEntersWhenLeaseExpires) {
    sx::cfg::CfgWriteGate gate({}, [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    ASSERT_TRUE(gate.acquire(
        "revision-1", "gui", [] { return "revision-1"; }, 20ms));

    EXPECT_TRUE(gate.enter_wait(config_mutex, 10ms, [](auto) { return true; }));
}

TEST(CfgWriteGate, ExpiredLeaseAllowsOrdinaryWriter) {
    auto now = sx::cfg::CfgLease::Clock::time_point {};
    sx::cfg::CfgWriteGate gate(
        [&now] { return now; },
        [] { return "lease-token"; });
    std::recursive_mutex config_mutex;
    ASSERT_TRUE(gate.acquire(
        "revision-1", "gui", [] { return "revision-1"; }, 15s));

    now += 15s;

    EXPECT_TRUE(gate.enter(config_mutex));
}

TEST(CfgWriteGate, ValidChecksLeaseAndCurrentRevisionTogether) {
    auto now = sx::cfg::CfgLease::Clock::time_point {};
    sx::cfg::CfgWriteGate gate(
        [&now] { return now; },
        [] { return "lease-token"; });
    ASSERT_TRUE(gate.acquire(
        "revision-1", "gui", [] { return "revision-1"; }, 15s));

    EXPECT_TRUE(gate.valid("lease-token", "revision-1", [] { return "revision-1"; }));
    EXPECT_FALSE(gate.valid("lease-token", "revision-1", [] { return "revision-2"; }));

    now += 15s;
    EXPECT_FALSE(gate.valid("lease-token", "revision-1", [] { return "revision-1"; }));
}

TEST(CfgWriteGate, GuardCanReleaseOnlyTheConfigMutex) {
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;
    auto guard = gate.enter(config_mutex);
    ASSERT_TRUE(guard);

    EXPECT_TRUE(guard->while_config_unlocked([&config_mutex] {
        const bool locked = config_mutex.try_lock();
        if(locked) config_mutex.unlock();
        return locked;
    }));

    auto waiting_writer = std::async(std::launch::async, [&gate, &config_mutex] {
        return gate.enter(config_mutex).has_value();
    });
    EXPECT_EQ(waiting_writer.wait_for(20ms), std::future_status::timeout);

    guard.reset();
    EXPECT_TRUE(waiting_writer.get());
}

TEST(CfgWriteGate, ReacquiresConfigMutexAfterUnlockedOperationThrows) {
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex config_mutex;
    auto guard = gate.enter(config_mutex);
    ASSERT_TRUE(guard);

    EXPECT_THROW(
        guard->while_config_unlocked([]() -> bool {
            throw std::runtime_error("runtime apply failed");
        }),
        std::runtime_error);

    auto locked_elsewhere = std::async(std::launch::async, [&config_mutex] {
        const bool locked = config_mutex.try_lock();
        if(locked) config_mutex.unlock();
        return locked;
    });
    EXPECT_FALSE(locked_elsewhere.get());
}
