#include <proxy/startstoptls.hpp>

#include <proxy/mitmcom.hpp>
#include <proxy/mitmhost.hpp>
#include <proxy/mitmproxy.hpp>
#include <service/cfgapi/cfgapi.hpp>

#include <sslcom.hpp>

MitmHostCX* StartStopTls::checked_peer(MitmHostCX& client, bool expect_tls) const {
    auto* peer = MitmHostCX::from_baseHostCX(client.peer());
    if(not peer) {
        return nullptr;
    }

    if(client.parent_proxy() != &owner_ or peer->parent_proxy() != &owner_) {
        return nullptr;
    }

    auto const client_is_tls = dynamic_cast<SSLCom*>(client.com()) != nullptr;
    auto const peer_is_tls = dynamic_cast<SSLCom*>(peer->com()) != nullptr;
    if(client_is_tls != expect_tls or peer_is_tls != expect_tls) {
        return nullptr;
    }

    return peer;
}

bool StartStopTls::start(MitmHostCX& client) {
    auto* peer = checked_peer(client, false);
    if(not peer) {
        return false;
    }

    auto* client_master = client.com()->master();
    auto* peer_master = peer->com()->master();

    auto* new_client_com = new MySSLMitmCom();
    auto* new_peer_com = new MySSLMitmCom();
    client.com(new_client_com);
    peer->com(new_peer_com);

    client.peer(peer);
    peer->peer(&client);

    client.com()->master(client_master);
    peer->com()->master(peer_master);

    // The accepted/client side cannot start its server handshake before the
    // upstream/client side has enough information to spoof the certificate.
    client.waiting_for_peercom(true);

    new_peer_com->upgrade_client_socket(peer->socket());
    new_client_com->upgrade_server_socket(client.socket());

    // Preserve the existing STARTTLS behaviour: spoofing may initialize the
    // accepted side once more after the upstream hello is available.
    new_client_com->upgraded(false);

    CfgFactory::get()->policy_apply_tls(client.matched_policy(), client.com());
    CfgFactory::get()->policy_apply_tls(client.matched_policy(), client.peercom());

    client.comlog().append(
            "\n STARTTLS: plain connection upgraded to SSL/TLS, continuing with inspection.\n\n");
    client.opening(true);

    return true;
}
