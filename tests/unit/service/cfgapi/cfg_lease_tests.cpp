#include <gtest/gtest.h>

#include <service/cfgapi/cfg_lease.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

TEST(CfgLease, GrantsOneRevisionBoundToken) {
    sx::cfg::CfgLease lease({}, [] { return "lease-token"; });

    auto const grant = lease.acquire("revision-1", "gui");

    ASSERT_TRUE(grant);
    EXPECT_EQ(grant->token, "lease-token");
    EXPECT_EQ(grant->base_revision, "revision-1");
    EXPECT_EQ(grant->owner, "gui");
    EXPECT_TRUE(lease.valid("lease-token", "revision-1"));
    EXPECT_FALSE(lease.valid("lease-token", "revision-2"));
}

TEST(CfgLease, RejectsAnotherOwnerUntilRelease) {
    sx::cfg::CfgLease lease({}, [] { return "lease-token"; });
    ASSERT_TRUE(lease.acquire("revision-1", "gui-1"));

    EXPECT_FALSE(lease.acquire("revision-1", "gui-2"));
    EXPECT_FALSE(lease.release("wrong-token"));
    EXPECT_TRUE(lease.release("lease-token"));
    EXPECT_TRUE(lease.acquire("revision-1", "gui-2"));
}

TEST(CfgLease, ExpiresAbandonedGrant) {
    auto now = sx::cfg::CfgLease::Clock::time_point {};
    sx::cfg::CfgLease lease([&now] { return now; }, [] { return "lease-token"; });
    ASSERT_TRUE(lease.acquire("revision-1", "gui", 15s));

    now += 15s;

    EXPECT_FALSE(lease.active());
    EXPECT_FALSE(lease.valid("lease-token", "revision-1"));
    EXPECT_TRUE(lease.acquire("revision-1", "cli"));
}

TEST(CfgLease, AllowsOnlyOneConcurrentGrant) {
    sx::cfg::CfgLease lease({}, [] { return "lease-token"; });
    std::atomic_int grants {0};
    std::vector<std::thread> clients;

    for(int client = 0; client < 8; ++client) {
        clients.emplace_back([&lease, &grants, client] {
            if(lease.acquire("revision-1", "client-" + std::to_string(client))) {
                ++grants;
            }
        });
    }
    for(auto& client: clients) client.join();

    EXPECT_EQ(grants, 1);
}

TEST(CfgLease, RejectsInvalidRequests) {
    sx::cfg::CfgLease lease;

    EXPECT_THROW((void)lease.acquire("", "gui"), std::invalid_argument);
    EXPECT_THROW((void)lease.acquire("revision-1", ""), std::invalid_argument);
    EXPECT_THROW((void)lease.acquire("revision-1", "gui", 0s), std::invalid_argument);
}

TEST(CfgLease, RejectsEmptyGeneratedToken) {
    sx::cfg::CfgLease lease({}, [] { return std::string {}; });

    EXPECT_THROW((void)lease.acquire("revision-1", "gui"), std::runtime_error);
}
