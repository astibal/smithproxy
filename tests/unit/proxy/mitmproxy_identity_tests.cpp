#include <gtest/gtest.h>

#include <proxy/connection_identity.hpp>

TEST(MitmProxyIdentity, FormatsStableUniqueOpaqueSessionIds) {
    auto const first_id = sx::proxy::connection_id(0x1234ABCDU, 1U);
    auto const second_id = sx::proxy::connection_id(0x1234ABCDU, 2U);

    EXPECT_EQ(first_id, sx::proxy::connection_id(0x1234ABCDU, 1U));
    EXPECT_NE(first_id, second_id);
    EXPECT_EQ(first_id, "Proxy-1234ABCD-SID-1");
    EXPECT_EQ(second_id, "Proxy-1234ABCD-SID-2");
    EXPECT_EQ(first_id.find("PTR"), std::string::npos);
}
