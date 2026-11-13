#pragma once

#include "proxy/multiflow/multiflow.hpp"
#include <openssl/ssl.h>
#include <string>

namespace sx::quic {
struct datagram_endpoint;
class keylog_store;

/**
 * Worker-owned QUIC leg exposed to the shared MITM lifecycle. Both backends use
 * OpenSSL for TLS, so certificate policy and hooks can inspect the same TLS API
 * without knowing which library owns QUIC packets, timers or stream state.
 */
class transport_connection : public multiflow::connection {
public:
    /** Borrow the TLS object; all access remains on this connection's worker. */
    virtual SSL* handle_native() const = 0;
    virtual datagram_endpoint peer_endpoint() const = 0;
    virtual bool handshake_complete() const = 0;
    virtual bool closed() const = 0;
    virtual std::string server_name() const = 0;
    std::string negotiated_alpn() const override = 0;
    virtual std::shared_ptr<keylog_store> keylog() const = 0;
    /** Service TLS/shutdown without consuming pending application events. */
    virtual void progress_transport() = 0;
    /** Consume a hint that application work requires another transport pass. */
    virtual bool take_application_progress() = 0;
};
} // namespace sx::quic
