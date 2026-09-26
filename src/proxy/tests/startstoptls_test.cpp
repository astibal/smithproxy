#include <gtest/gtest.h>

#include <proxy/startstoptls.hpp>

using PairState = StartStopTls::PairState;
using PairStatus = StartStopTls::PairStatus;

TEST(StartStopTlsValidation, PlainPairCanStartTls) {
    PairState const state {
        .has_peer = true,
        .client_owned = true,
        .peer_owned = true,
        .client_tls = false,
        .peer_tls = false
    };

    EXPECT_EQ(StartStopTls::validate(state, false), PairStatus::Ready);
}

TEST(StartStopTlsValidation, TlsPairCannotStartTlsAgain) {
    PairState const state {
        .has_peer = true,
        .client_owned = true,
        .peer_owned = true,
        .client_tls = true,
        .peer_tls = true
    };

    EXPECT_EQ(StartStopTls::validate(state, false), PairStatus::UnexpectedTransport);
}

TEST(StartStopTlsValidation, TlsPairIsEligibleForStopTls) {
    PairState const state {
        .has_peer = true,
        .client_owned = true,
        .peer_owned = true,
        .client_tls = true,
        .peer_tls = true
    };

    EXPECT_EQ(StartStopTls::validate(state, true), PairStatus::Ready);
}

TEST(StartStopTlsValidation, MissingPeerIsRejected) {
    PairState const state {
        .has_peer = false,
        .client_owned = true,
        .peer_owned = false,
        .client_tls = false,
        .peer_tls = false
    };

    EXPECT_EQ(StartStopTls::validate(state, false), PairStatus::MissingPeer);
}

TEST(StartStopTlsValidation, ForeignClientIsRejected) {
    PairState const state {
        .has_peer = true,
        .client_owned = false,
        .peer_owned = true,
        .client_tls = false,
        .peer_tls = false
    };

    EXPECT_EQ(StartStopTls::validate(state, false), PairStatus::ForeignOwner);
}

TEST(StartStopTlsValidation, ForeignPeerIsRejected) {
    PairState const state {
        .has_peer = true,
        .client_owned = true,
        .peer_owned = false,
        .client_tls = false,
        .peer_tls = false
    };

    EXPECT_EQ(StartStopTls::validate(state, false), PairStatus::ForeignOwner);
}

TEST(StartStopTlsValidation, TlsClientWithPlainPeerIsRejected) {
    PairState const state {
        .has_peer = true,
        .client_owned = true,
        .peer_owned = true,
        .client_tls = true,
        .peer_tls = false
    };

    EXPECT_EQ(StartStopTls::validate(state, false), PairStatus::AsymmetricTransport);
}

TEST(StartStopTlsValidation, PlainClientWithTlsPeerIsRejected) {
    PairState const state {
        .has_peer = true,
        .client_owned = true,
        .peer_owned = true,
        .client_tls = false,
        .peer_tls = true
    };

    EXPECT_EQ(StartStopTls::validate(state, false), PairStatus::AsymmetricTransport);
}
