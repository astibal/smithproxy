#include <buildprofile.hpp>
#include <sslcertstore.hpp>

#include <gtest/gtest.h>

namespace {

static_assert(sx::build_profile::mem_constrained);
static_assert(sx::build_profile::utility_workers == 5U);
static_assert(!sx::build_profile::cli_enabled);
static_assert(sx::build_profile::configured_utility_workers(128U, 32U) == 5U);

TEST(BuildProfile, ConstrainedValuesArePartOfTheExecutable) {
    EXPECT_TRUE(sx::build_profile::mem_constrained);
    EXPECT_EQ(sx::build_profile::utility_workers, 5U);
    EXPECT_FALSE(sx::build_profile::cli_enabled);
    EXPECT_EQ(sx::build_profile::configured_utility_workers(128U, 32U), 5U);
    EXPECT_EQ(SSLFactory::config_t::CERTSTORE_CACHE_SIZE, 64U);
    EXPECT_EQ(SSLFactory::config_t::VERIFY_CACHE_SIZE, 64U);
    EXPECT_EQ(SSLFactory::config_t::SESSION_CACHE_SIZE, 32U);
    EXPECT_EQ(SSLFactory::config_t::CRL_CACHE_SIZE, 16U);
}

TEST(BuildProfile, HeapTrimRequiresAQuietWindowAndCooldown) {
    using namespace std::chrono_literals;
    using schedule = sx::build_profile::heap_trim_schedule;

    const schedule::time_point start{};
    schedule trim{10U, start};

    for (auto elapsed = 10s; elapsed < 60s; elapsed += 10s) {
        EXPECT_FALSE(trim.observe(10U, start + elapsed));
    }
    EXPECT_FALSE(trim.observe(10U, start + 59s));
    EXPECT_TRUE(trim.observe(10U, start + 60s));
    EXPECT_FALSE(trim.observe(10U, start + 70s));
    EXPECT_FALSE(trim.observe(11U, start + 110s));
    EXPECT_TRUE(trim.observe(11U, start + 120s));
}

TEST(BuildProfile, NewSessionRestartsTheQuietWindow) {
    using namespace std::chrono_literals;
    using schedule = sx::build_profile::heap_trim_schedule;

    const schedule::time_point start{};
    schedule trim{20U, start};

    EXPECT_FALSE(trim.observe(21U, start + 60s));
    EXPECT_FALSE(trim.observe(22U, start + 69s));
    EXPECT_FALSE(trim.observe(22U, start + 70s));
    EXPECT_TRUE(trim.observe(22U, start + 80s));
}

} // namespace
