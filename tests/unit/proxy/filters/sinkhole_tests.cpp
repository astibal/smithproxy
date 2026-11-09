#include <gtest/gtest.h>

#include <proxy/filters/sinkhole.hpp>

#include <tcpcom.hpp>

namespace {

TEST(SinkholeFilter, MissingEndpointsAreIgnoredSafely) {
    SinkholeFilter filter(nullptr, true, true);
    baseHostCX endpoint(new TCPCom(), -1);

    EXPECT_NO_THROW(filter.proxy(nullptr, &endpoint, socle::side_t::LEFT, false));
    EXPECT_NO_THROW(filter.proxy(&endpoint, nullptr, socle::side_t::RIGHT, false));
    EXPECT_EQ(filter.left_sunken, 0U);
    EXPECT_EQ(filter.right_sunken, 0U);
}

TEST(SinkholeFilter, ClearsSelectedDirectionAndAccountsOriginalBytes) {
    SinkholeFilter filter(nullptr, true, false);
    baseHostCX from(new TCPCom(), -1);
    baseHostCX to(new TCPCom(), -1);
    from.readbuf()->assign("payload");

    filter.proxy(&from, &to, socle::side_t::LEFT, false);

    EXPECT_TRUE(from.readbuf()->empty());
    EXPECT_EQ(filter.left_sunken, 7U);
    EXPECT_EQ(filter.right_sunken, 0U);
    EXPECT_EQ(from.idle_delay(), 30);
    EXPECT_EQ(to.idle_delay(), 30);
}

TEST(SinkholeFilter, ReplacementDoesNotInflateAccounting) {
    SinkholeFilter filter(nullptr, false, true);
    filter.replacement = "blocked";
    baseHostCX from(new TCPCom(), -1);
    baseHostCX to(new TCPCom(), -1);
    from.readbuf()->assign("original-data");

    filter.proxy(&from, &to, socle::side_t::RIGHT, false);

    EXPECT_EQ(from.readbuf()->str(), "blocked");
    EXPECT_EQ(filter.right_sunken, 13U);
    EXPECT_EQ(filter.to_json(iINF).at("replacement_size"), 7U);
}

TEST(SinkholeFilter, DisabledDirectionLeavesDataUntouched) {
    SinkholeFilter filter(nullptr, false, false);
    baseHostCX from(new TCPCom(), -1);
    baseHostCX to(new TCPCom(), -1);
    from.readbuf()->assign("payload");

    filter.proxy(&from, &to, socle::side_t::LEFT, false);

    EXPECT_EQ(from.readbuf()->str(), "payload");
    EXPECT_EQ(filter.left_sunken, 0U);
}

} // namespace
