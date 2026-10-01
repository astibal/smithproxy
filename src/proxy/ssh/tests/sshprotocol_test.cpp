#include <gtest/gtest.h>

#include <proxy/ssh/sshprotocol.hpp>

using namespace sx::ssh;

TEST(SshIdentification, ParsesSsh2ServerBannerIncrementally) {
    identification_parser parser(true);

    EXPECT_EQ(parser.feed("maintenance\r\nSSH-2."), parse_status::need_more);
    EXPECT_EQ(parser.feed("0-OpenSSH_9.7 Debian-7\r\n"), parse_status::complete);

    EXPECT_EQ(parser.result().version, protocol_version::ssh2);
    EXPECT_EQ(parser.result().protocol, "2.0");
    EXPECT_EQ(parser.result().software, "OpenSSH_9.7");
    EXPECT_EQ(parser.result().comments, "Debian-7");
    EXPECT_EQ(parser.result().raw, "SSH-2.0-OpenSSH_9.7 Debian-7");
    ASSERT_EQ(parser.result().preamble.size(), 1U);
    EXPECT_EQ(parser.result().preamble.front(), "maintenance");
}

TEST(SshIdentification, TreatsCompatibilityBannerAsSsh2) {
    identification_parser parser(false);
    EXPECT_EQ(parser.feed("SSH-1.99-OpenSSH_3.9\r\n"), parse_status::complete);
    EXPECT_EQ(parser.result().version, protocol_version::ssh2);
}

TEST(SshIdentification, ClassifiesProtocolOneForBlocking) {
    identification_parser parser(false);
    EXPECT_EQ(parser.feed("SSH-1.5-OpenSSH_3.5\r\n"), parse_status::complete);
    EXPECT_EQ(parser.result().version, protocol_version::ssh1);
}

TEST(SshIdentification, RejectsClientPreamble) {
    identification_parser parser(false);
    EXPECT_EQ(parser.feed("hello\r\nSSH-2.0-client\r\n"), parse_status::invalid);
}

TEST(SshIdentification, RejectsOversizedIdentification) {
    identification_parser parser(false);
    std::string banner = "SSH-2.0-" + std::string(246, 'x') + "\r\n";
    EXPECT_EQ(parser.feed(banner), parse_status::invalid);
}

TEST(SshMitmState, FollowsRequiredHandshakeOrder) {
    EXPECT_TRUE(transition_allowed(mitm_state::detect, mitm_state::upstream_connect));
    EXPECT_TRUE(transition_allowed(mitm_state::upstream_connect, mitm_state::server_identification));
    EXPECT_TRUE(transition_allowed(mitm_state::server_identification, mitm_state::client_identification));
    EXPECT_TRUE(transition_allowed(mitm_state::client_identification, mitm_state::key_exchange));
    EXPECT_TRUE(transition_allowed(mitm_state::key_exchange, mitm_state::authentication));
    EXPECT_TRUE(transition_allowed(mitm_state::authentication, mitm_state::channels));

    EXPECT_FALSE(transition_allowed(mitm_state::server_identification, mitm_state::key_exchange));
    EXPECT_TRUE(transition_allowed(mitm_state::server_identification, mitm_state::blocked));
    EXPECT_TRUE(transition_allowed(mitm_state::channels, mitm_state::closing));
    EXPECT_TRUE(transition_allowed(mitm_state::closing, mitm_state::closed));
}

TEST(SshMitmState, PreservesRealServerBannerBeforeClientHandshake) {
    handshake_fsm fsm;
    ASSERT_TRUE(fsm.begin_upstream_connect());
    ASSERT_TRUE(fsm.upstream_connected());

    EXPECT_EQ(fsm.feed_server_identification(
        "notice\r\nSSH-2.0-OpenSSH_9.8 production\r\n"), parse_status::complete);
    EXPECT_EQ(fsm.state(), mitm_state::client_identification);
    EXPECT_EQ(fsm.server_identification().raw,
              "SSH-2.0-OpenSSH_9.8 production");

    EXPECT_EQ(fsm.feed_client_identification(
        "SSH-2.0-PuTTY_Release_0.83\r\n"), parse_status::complete);
    EXPECT_EQ(fsm.state(), mitm_state::key_exchange);
}

TEST(SshMitmState, BlocksProtocolOneBeforeKeyExchange) {
    handshake_fsm fsm;
    ASSERT_TRUE(fsm.begin_upstream_connect());
    ASSERT_TRUE(fsm.upstream_connected());

    EXPECT_EQ(fsm.feed_server_identification(
        "SSH-1.5-legacy-server\r\n"), parse_status::complete);
    EXPECT_EQ(fsm.state(), mitm_state::blocked);
    EXPECT_EQ(fsm.error(), "SSH protocol version 1 is blocked");
}
