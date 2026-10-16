#include "live_listener_lifecycle.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace {

using smithproxy::live::Listener;
using smithproxy::live::Workers;

TEST(LiveListenerLifecycle, UnchangedSettingDoesNothing) {
    int stops = 0;
    EXPECT_TRUE(smithproxy::live::apply_listener(
        true, [] { return true; }, [&] { ++stops; },
        [] { return false; }, [] { FAIL() << "must not launch"; }));
    EXPECT_EQ(stops, 0);
}

TEST(LiveListenerLifecycle, DisableStopsWithoutCreatingReplacement) {
    int stops = 0;
    EXPECT_TRUE(smithproxy::live::apply_listener(
        true, [] { return false; }, [&] { ++stops; },
        [] { return false; }, [] { FAIL() << "must not launch"; }));
    EXPECT_EQ(stops, 1);
}

TEST(LiveListenerLifecycle, EnableCreatesAndLaunches) {
    int stops = 0;
    int launches = 0;
    EXPECT_TRUE(smithproxy::live::apply_listener(
        false, [] { return true; }, [&] { ++stops; },
        [] { return true; }, [&] { ++launches; }));
    EXPECT_EQ(stops, 1);
    EXPECT_EQ(launches, 1);
}

TEST(LiveListenerLifecycle, FailedCreateCleansPartialGroup) {
    int stops = 0;
    EXPECT_FALSE(smithproxy::live::apply_listener(
        false, [] { return true; }, [&] { ++stops; },
        [] { return false; }, [] { FAIL() << "must not launch"; }));
    EXPECT_EQ(stops, 2);
}

TEST(LiveListenerLifecycle, WorkerGroupsRouteToTheirListeners) {
    std::vector<Listener> restarted;
    auto restart = [&](Listener listener) {
        restarted.push_back(listener);
        return true;
    };

    EXPECT_TRUE(smithproxy::live::apply_workers(Workers::tproxy, restart));
    EXPECT_EQ(restarted, (std::vector<Listener>{Listener::tproxy, Listener::redirect}));
    restarted.clear();
    EXPECT_TRUE(smithproxy::live::apply_workers(Workers::socks, restart));
    EXPECT_EQ(restarted, (std::vector<Listener>{Listener::socks}));
    restarted.clear();
    EXPECT_TRUE(smithproxy::live::apply_workers(Workers::http_connect, restart));
    EXPECT_EQ(restarted, (std::vector<Listener>{Listener::http_connect}));
}

TEST(LiveListenerLifecycle, TproxyWorkerRestartShortCircuitsOnFailure) {
    std::vector<Listener> restarted;
    EXPECT_FALSE(smithproxy::live::apply_workers(Workers::tproxy, [&](Listener listener) {
        restarted.push_back(listener);
        return false;
    }));
    EXPECT_EQ(restarted, (std::vector<Listener>{Listener::tproxy}));
}

}  // namespace
