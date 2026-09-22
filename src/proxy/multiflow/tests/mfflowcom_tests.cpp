#include <array>
#include <cerrno>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "proxy/multiflow/fake.hpp"
#include "proxy/multiflow/mfflowcom.hpp"

namespace mf = sx::multiflow;

TEST(MFFlowCom, PeekDoesNotConsumeFlowData) {
    auto connection = std::make_shared<mf::fake_connection>();
    auto const flow = connection->open_flow(mf::direction::bidirectional);
    mf::MFFlowCom com(connection, flow);
    std::string const payload = "client hello";
    ASSERT_EQ(connection->inject_receive(flow, payload.data(), payload.size()), mf::io_status::ok);

    std::array<char, 32> peeked {};
    std::array<char, 32> read {};
    ASSERT_EQ(com.peek(com.token(), peeked.data(), payload.size(), 0),
              static_cast<ssize_t>(payload.size()));
    ASSERT_EQ(com.read(com.token(), read.data(), payload.size(), 0),
              static_cast<ssize_t>(payload.size()));
    EXPECT_EQ(std::string(peeked.data(), payload.size()), payload);
    EXPECT_EQ(std::string(read.data(), payload.size()), payload);
}

TEST(MFFlowCom, MapsBackpressureForBaseHostCX) {
    auto connection = std::make_shared<mf::fake_connection>(4);
    auto const flow = connection->open_flow(mf::direction::bidirectional);
    mf::MFFlowCom com(connection, flow);
    std::string const payload = "abcdef";

    EXPECT_EQ(com.write(com.token(), payload.data(), payload.size(), 0), 4);
    errno = 0;
    EXPECT_EQ(com.write(com.token(), payload.data(), payload.size(), 0), 0);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_FALSE(com.writable(com.token()));

    connection->consume_send(flow, 2);
    EXPECT_TRUE(com.writable(com.token()));
}

TEST(MFFlowCom, ShutdownFinishesOnlyOwnedFlow) {
    auto connection = std::make_shared<mf::fake_connection>();
    auto const first = connection->open_flow(mf::direction::bidirectional);
    auto const second = connection->open_flow(mf::direction::bidirectional);
    mf::MFFlowCom first_com(connection, first);
    mf::MFFlowCom second_com(connection, second);

    first_com.shutdown(first_com.token());
    EXPECT_FALSE(first_com.writable(first_com.token()));
    EXPECT_TRUE(second_com.writable(second_com.token()));
    EXPECT_TRUE(connection->contains(second));
}

