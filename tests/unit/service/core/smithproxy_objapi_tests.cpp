#include <gtest/gtest.h>

#include <service/core/smithproxy_objapi_utils.hpp>

TEST(ObjApi, NeighborAgeHandlesBoundariesAndFutureClockSkew) {
    EXPECT_TRUE(sx::objapi::day_is_within_age(100, 100, 0));
    EXPECT_TRUE(sx::objapi::day_is_within_age(100, 99, 1));
    EXPECT_FALSE(sx::objapi::day_is_within_age(100, 98, 1));
    EXPECT_TRUE(sx::objapi::day_is_within_age(100, 101, 0));
}
