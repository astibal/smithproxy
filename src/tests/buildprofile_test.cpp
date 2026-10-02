#include <buildprofile.hpp>

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
}

} // namespace
