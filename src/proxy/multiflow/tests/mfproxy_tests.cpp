#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "proxy/multiflow/fake.hpp"
#include "proxy/multiflow/mfproxy.hpp"

namespace mf = sx::multiflow;

TEST(MFProxy, PairsAndPumpsBidirectionalFlows) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>();
    mf::MFProxy proxy(left, right);

    auto const left_flow = left->open_flow(mf::direction::bidirectional);
    proxy.pump_once();
    ASSERT_EQ(proxy.pair_count(), 1U);

    std::string const request = "request";
    ASSERT_EQ(left->inject_receive(left_flow, request.data(), request.size()), mf::io_status::ok);
    EXPECT_EQ(proxy.pump_once(), request.size());

    // The paired right-side flow is the only flow and uses the first fake ID.
    mf::flow_handle const right_flow { 0, 1 };
    auto const sent = right->consume_send(right_flow);
    EXPECT_EQ(std::string(sent.begin(), sent.end()), request);

    std::string const response = "response";
    ASSERT_EQ(right->inject_receive(right_flow, response.data(), response.size()), mf::io_status::ok);
    EXPECT_EQ(proxy.pump_once(), response.size());
    auto const returned = left->consume_send(left_flow);
    EXPECT_EQ(std::string(returned.begin(), returned.end()), response);
}

TEST(MFProxy, RetainsDataAcrossDestinationBackpressure) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>(3);
    mf::MFProxy proxy(left, right);
    auto const flow = left->open_flow(mf::direction::bidirectional);
    proxy.pump_once();

    std::string const payload = "123456";
    left->inject_receive(flow, payload.data(), payload.size());
    EXPECT_EQ(proxy.pump_once(), 3U);
    mf::flow_handle const right_flow { 0, 1 };
    auto first = right->consume_send(right_flow);
    EXPECT_EQ(std::string(first.begin(), first.end()), "123");
    EXPECT_EQ(proxy.pump_once(), 3U);
    auto second = right->consume_send(right_flow);
    EXPECT_EQ(std::string(second.begin(), second.end()), "456");
}

TEST(MFProxy, MirrorsIncomingUnidirectionalFlowAsSendOnly) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>();
    mf::MFProxy proxy(left, right);
    auto const incoming = left->open_flow(mf::direction::receive_only);
    proxy.pump_once();
    ASSERT_EQ(proxy.pair_count(), 1U);

    mf::flow_handle const outgoing { 0, 1 };
    ASSERT_EQ(right->direction_of(outgoing), mf::direction::send_only);
    std::string const data = "uni";
    left->inject_receive(incoming, data.data(), data.size());
    EXPECT_EQ(proxy.pump_once(), data.size());
    auto sent = right->consume_send(outgoing);
    EXPECT_EQ(std::string(sent.begin(), sent.end()), data);
}

TEST(MFProxy, MirrorsRightIncomingUnidirectionalFlowAsSendOnly) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>();
    mf::MFProxy proxy(left, right);
    auto const incoming = right->open_flow(mf::direction::receive_only);
    proxy.pump_once();
    ASSERT_EQ(proxy.pair_count(), 1U);

    mf::flow_handle const outgoing { 0, 1 };
    ASSERT_EQ(left->direction_of(outgoing), mf::direction::send_only);
    std::string const data = "reverse-uni";
    right->inject_receive(incoming, data.data(), data.size());
    EXPECT_EQ(proxy.pump_once(), data.size());
    auto sent = left->consume_send(outgoing);
    EXPECT_EQ(std::string(sent.begin(), sent.end()), data);
}

TEST(MFProxy, PropagatesFinOnlyAfterPendingData) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>(3);
    mf::MFProxy proxy(left, right);
    auto const left_flow = left->open_flow(mf::direction::bidirectional);
    proxy.pump_once();
    mf::flow_handle const right_flow { 0, 1 };

    std::string const payload = "abcdef";
    left->inject_receive(left_flow, payload.data(), payload.size());
    left->inject_peer_fin(left_flow);
    EXPECT_EQ(proxy.pump_once(), 3U);
    EXPECT_FALSE(right->local_finished(right_flow));

    right->consume_send(right_flow);
    EXPECT_EQ(proxy.pump_once(), 3U);
    EXPECT_TRUE(right->local_finished(right_flow));
}

TEST(MFProxy, RetriesFinAfterTransportBackpressure) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>();
    mf::MFProxy proxy(left, right);
    auto const left_flow = left->open_flow(mf::direction::bidirectional);
    proxy.pump_once();
    mf::flow_handle const right_flow { 0, 1 };

    right->block_finish(right_flow, true);
    left->inject_peer_fin(left_flow);
    proxy.pump_once();
    EXPECT_FALSE(right->local_finished(right_flow));

    right->block_finish(right_flow, false);
    proxy.pump_once();
    EXPECT_TRUE(right->local_finished(right_flow));
}

TEST(MFProxy, PropagatesResetCodeAndRetiresPair) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>();
    mf::MFProxy proxy(left, right);
    auto const left_flow = left->open_flow(mf::direction::bidirectional);
    proxy.pump_once();
    mf::flow_handle const right_flow { 0, 1 };

    left->reset(left_flow, 0x107);
    proxy.pump_once();
    ASSERT_TRUE(right->reset_code(right_flow));
    EXPECT_EQ(*right->reset_code(right_flow), 0x107U);
    EXPECT_EQ(proxy.pair_count(), 0U);
}

TEST(MFProxy, PropagatesConnectionClose) {
    auto left = std::make_shared<mf::fake_connection>();
    auto right = std::make_shared<mf::fake_connection>();
    mf::MFProxy proxy(left, right);
    left->close(23);
    proxy.pump_once();

    auto const events = right->drain_events();
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events.front().type, mf::event_type::connection_close);
    EXPECT_EQ(events.front().protocol_error, 23U);
}
