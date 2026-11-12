#include <array>
#include <cerrno>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "proxy/multiflow/fake.hpp"
#include "proxy/multiflow/mfflowcom.hpp"
#include "proxy/connection_transport.hpp"
#include <tcpcom.hpp>
#include <masterproxy.hpp>
#include <udpcom.hpp>

namespace mf = sx::multiflow;

TEST(MFFlowCom, KeepsStreamIoButReportsUdpToPolicy) {
    auto connection = std::make_shared<mf::fake_connection>(
        64 * 1024, mf::outer_transport::udp);
    auto const flow = connection->open_flow(mf::direction::bidirectional);
    mf::MFFlowCom com(connection, flow);
    EXPECT_TRUE(com.descriptor_valid(com.token()));
    EXPECT_FALSE(com.descriptor_valid(-1));
    EXPECT_FALSE(com.descriptor_valid(0));

    // MitmProxy requires stream lifecycle semantics for each QUIC stream. The
    // policy engine must nevertheless match the enclosing UDP/QUIC flow.
    EXPECT_EQ(SOCK_STREAM, com.l4_proto());
    EXPECT_EQ(SOCK_DGRAM, com.policy_l4_proto());
}

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

TEST(MFFlowCom, ZeroLengthIoDoesNotTouchTransportState) {
    auto connection = std::make_shared<mf::fake_connection>();
    auto const flow = connection->open_flow(mf::direction::bidirectional);
    mf::MFFlowCom com(connection, flow);

    EXPECT_EQ(com.read(com.token(), nullptr, 0, 0), 0);
    EXPECT_EQ(com.peek(com.token(), nullptr, 0, 0), 0);
    EXPECT_EQ(com.write(com.token(), nullptr, 0, 0), 0);

    connection->close();
    EXPECT_EQ(com.read(com.token(), nullptr, 0, 0), 0);
    EXPECT_EQ(com.write(com.token(), nullptr, 0, 0), 0);
}

TEST(MFFlowCom, DefersPeerFinForIndependentHalfClose) {
    auto connection = std::make_shared<mf::fake_connection>();
    auto const flow = connection->open_flow(mf::direction::bidirectional);
    mf::MFFlowCom com(connection, flow);
    com.defer_read_eof(true);
    ASSERT_EQ(connection->inject_peer_fin(flow), mf::io_status::ok);

    std::array<char, 1> byte {};
    errno = 0;
    EXPECT_EQ(-1, com.read(com.token(), byte.data(), byte.size(), 0));
    EXPECT_EQ(EAGAIN, errno);
    EXPECT_FALSE(com.readable(com.token()));
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

TEST(MFFlowCom, ConnectionStartMetadataUsesThePhysicalCarrier) {
    for (auto const carrier : {mf::outer_transport::udp, mf::outer_transport::tcp}) {
        auto connection = std::make_shared<mf::fake_connection>(64 * 1024, carrier);
        auto flow = connection->open_flow(mf::direction::bidirectional);
        mf::MFFlowCom com(connection, flow);
        nlohmann::json info = nlohmann::json::object();

        sx::proxy::add_connection_transport(info, com);

        EXPECT_EQ(info.at("transport"), carrier == mf::outer_transport::udp ? "udp" : "tcp");
        EXPECT_EQ(com.l4_proto(), SOCK_STREAM);
    }
}

TEST(MFFlowCom, ConnectionStartMetadataPreservesOrdinaryTcpAndUdp) {
    TCPCom tcp;
    UDPCom udp;
    nlohmann::json info = nlohmann::json::object();
    sx::proxy::add_connection_transport(info, tcp);
    EXPECT_EQ(info.at("transport"), "tcp");
    sx::proxy::add_connection_transport(info, udp);
    EXPECT_EQ(info.at("transport"), "udp");
}

// Exercise the same parent accounting used by the production stream bridge:
// the last write and child removal happen inside a single master pump.

namespace {
class finishing_flow_proxy final : public baseProxy {
public:
    finishing_flow_proxy(std::shared_ptr<mf::fake_connection> connection, mf::flow_handle flow,
                         unsigned char side)
        : baseProxy(new TCPCom()), side_(side) {
        auto* com = new mf::MFFlowCom(std::move(connection), flow);
        output_ = std::make_unique<baseHostCX>(com, com->token());
        output_->opening(false);
        output_->writebuf()->append("last payload", 12);
        stats().do_rate_meter = false;
    }
    int handle_sockets_once(baseCom*) override {
        EXPECT_TRUE(handle_cx_write(side_, output_.get()));
        state().dead(true);
        return 1;
    }
private:
    unsigned char side_;
    std::unique_ptr<baseHostCX> output_;
};
}

TEST(MFFlowCom, ParentBytesSurviveFinalWriteAndChildRemovalInSamePump) {
    for (auto side : {'l', 'r'}) {
        auto connection = std::make_shared<mf::fake_connection>();
        auto flow = connection->open_flow(mf::direction::bidirectional);
        MasterProxy master(new TCPCom());
        master.add_proxy(std::make_unique<finishing_flow_proxy>(connection, flow, side));
        master.handle_sockets_once(master.com());
        EXPECT_TRUE(master.proxies().empty());
        EXPECT_EQ(master.stats().bytes_up(), side == 'r' ? 12U : 0U);
        EXPECT_EQ(master.stats().bytes_down(), side == 'l' ? 12U : 0U);
        auto const sent = connection->consume_send(flow);
        EXPECT_EQ(std::string(sent.begin(), sent.end()), "last payload");
        master.handle_sockets_once(master.com());
        EXPECT_EQ(master.stats().bytes_up() + master.stats().bytes_down(), 12U);
    }
}
