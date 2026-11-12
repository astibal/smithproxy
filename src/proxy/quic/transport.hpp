#pragma once
#include "proxy/quic/openssl.hpp"
#include <chrono>

namespace sx::quic {
#if SMITHPROXY_OPENSSL_QUIC

enum class transport_backend { openssl, ngtcp2, unavailable };
// Select ngtcp2 by default when built; OpenSSL remains an explicit alternative.
// Unknown or unavailable selections return unavailable, never a silent fallback.
transport_backend configured_transport_backend();
/** Create TLS contexts with the same central trust/CT store for either backend. */
unique_ssl_ctx make_transport_context(transport_backend backend, bool server);

/**
 * One worker's incoming and outgoing QUIC transport. Policy, certificate jobs,
 * stream MitmProxy children, capture journals and lifecycle stay in the service.
 * No method may run concurrently or move a connection to another worker.
 */
class worker_transport {
public:
    virtual ~worker_transport() = default;
    virtual bool handle_events() = 0;       ///< Bounded incoming receive/timer/TX pass.
    virtual bool handle_upstream() = 0;     ///< Equivalent pass for all B connections.
    virtual std::shared_ptr<transport_connection> accept() = 0;
    virtual std::shared_ptr<transport_connection> connect(
        SSL_CTX*, const sockaddr*, socklen_t, std::string const&, std::string*,
        proxymaker::SessionSetup*, std::function<bool(SSL*)> const&) = 0;
    virtual bool flush_output(datagram_endpoint const&, datagram_endpoint const&, uint64_t) = 0;
    /** Relative protocol deadline; negative means no deadline. */
    virtual std::chrono::nanoseconds timeout() const = 0;
    virtual short desired_socket_events() const = 0;
    virtual int upstream_fd() const = 0;
    virtual short upstream_events() const = 0;
    virtual std::string last_error() const = 0;
    /** Metadata scoped to the connection whose TLS callback is executing. */
    virtual datagram_endpoint current_peer() const = 0;
    virtual datagram_endpoint current_local() const = 0;
    virtual unsigned current_ingress_ifindex() const = 0;
    virtual uint64_t current_association() const = 0;
    virtual bool bind_connection_route(SSL*) = 0;
};

/** Attach a shared receiver source and packet observer without transferring fd ownership. */
std::unique_ptr<worker_transport> make_worker_transport(
    transport_backend, SSL_CTX* server, SSL_CTX* client, int fd, int family,
    bool transparent, datagram_observer observer, datagram_source source,
    size_t max_connections);
#endif
} // namespace sx::quic
