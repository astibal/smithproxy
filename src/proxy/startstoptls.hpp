/*
 * TLS transport transitions owned by a MitmProxy session.
 */

#ifndef SMITHPROXY_STARTSTOPTLS_HPP
#define SMITHPROXY_STARTSTOPTLS_HPP

class MitmHostCX;
class MitmProxy;

class StartStopTls {
public:
    enum class PairStatus {
        Ready,
        MissingPeer,
        ForeignOwner,
        AsymmetricTransport,
        UnexpectedTransport
    };

    struct PairState {
        bool has_peer = false;
        bool client_owned = false;
        bool peer_owned = false;
        bool client_tls = false;
        bool peer_tls = false;
    };

    explicit StartStopTls(MitmProxy& owner) noexcept : owner_(owner) {}

    StartStopTls(StartStopTls const&) = delete;
    StartStopTls& operator=(StartStopTls const&) = delete;

    // Upgrade a connected plaintext pair. `client` is the accepted/client side.
    bool start(MitmHostCX& client);

    static PairStatus validate(PairState const& state, bool expect_tls) noexcept {
        if(not state.has_peer) {
            return PairStatus::MissingPeer;
        }
        if(not state.client_owned or not state.peer_owned) {
            return PairStatus::ForeignOwner;
        }
        if(state.client_tls != state.peer_tls) {
            return PairStatus::AsymmetricTransport;
        }
        if(state.client_tls != expect_tls) {
            return PairStatus::UnexpectedTransport;
        }
        return PairStatus::Ready;
    }

private:
    MitmHostCX* checked_peer(MitmHostCX& client, bool expect_tls) const;

    MitmProxy& owner_;
};

#endif // SMITHPROXY_STARTSTOPTLS_HPP
