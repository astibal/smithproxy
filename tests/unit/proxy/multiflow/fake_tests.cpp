#include <array>
#include <string>

#include <gtest/gtest.h>

#include "proxy/multiflow/fake.hpp"

namespace mf = sx::multiflow;

TEST(MultiflowFake, FlowsHaveIndependentBuffersAndLifetime) {
    mf::fake_connection connection;
    auto const first = connection.open_flow(mf::direction::bidirectional);
    auto const second = connection.open_flow(mf::direction::bidirectional);
    connection.drain_events();

    std::string const first_data = "first";
    std::string const second_data = "second";
    EXPECT_EQ(connection.inject_receive(first, first_data.data(), first_data.size()), mf::io_status::ok);
    EXPECT_EQ(connection.inject_receive(second, second_data.data(), second_data.size()), mf::io_status::ok);

    std::array<char, 16> output {};
    auto result = connection.read(first, output.data(), output.size());
    EXPECT_EQ(result.status, mf::io_status::ok);
    EXPECT_EQ(std::string(output.data(), result.size), first_data);
    EXPECT_TRUE(connection.readable(second));

    EXPECT_EQ(connection.reset(first, 42), mf::io_status::ok);
    EXPECT_TRUE(connection.writable(second));
    EXPECT_EQ(connection.write(second, second_data.data(), second_data.size()).status, mf::io_status::ok);
}

TEST(MultiflowFake, FinIsDeliveredAfterBufferedData) {
    mf::fake_connection connection;
    auto const flow = connection.open_flow(mf::direction::bidirectional);
    std::string const data = "payload";

    ASSERT_EQ(connection.inject_receive(flow, data.data(), data.size()), mf::io_status::ok);
    ASSERT_EQ(connection.inject_peer_fin(flow), mf::io_status::ok);

    std::array<char, 16> output {};
    auto result = connection.read(flow, output.data(), output.size());
    EXPECT_EQ(result.status, mf::io_status::ok);
    EXPECT_EQ(std::string(output.data(), result.size), data);
    EXPECT_EQ(connection.read(flow, output.data(), output.size()).status, mf::io_status::eof);
}

TEST(MultiflowFake, BackpressureProducesOneWritableTransition) {
    mf::fake_connection connection(4);
    auto const flow = connection.open_flow(mf::direction::bidirectional);
    connection.drain_events();

    std::string const data = "abcdef";
    auto result = connection.write(flow, data.data(), data.size());
    EXPECT_EQ(result.size, 4U);
    EXPECT_EQ(result.status, mf::io_status::would_block);
    EXPECT_FALSE(connection.writable(flow));

    connection.consume_send(flow, 2);
    connection.consume_send(flow, 1);
    auto const events = connection.drain_events();
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events.front().type, mf::event_type::writable);
    EXPECT_EQ(events.front().flow, flow);
}

TEST(MultiflowFake, ConnectionCloseInvalidatesAllFlowOperations) {
    mf::fake_connection connection;
    auto const first = connection.open_flow(mf::direction::bidirectional);
    auto const second = connection.open_flow(mf::direction::bidirectional);
    connection.drain_events();

    connection.close(7);
    std::array<char, 1> byte {};
    EXPECT_EQ(connection.read(first, byte.data(), byte.size()).status, mf::io_status::connection_closed);
    EXPECT_EQ(connection.write(second, byte.data(), byte.size()).status, mf::io_status::connection_closed);

    auto const events = connection.drain_events();
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events.front().type, mf::event_type::connection_close);
    EXPECT_EQ(events.front().protocol_error, 7U);
}

