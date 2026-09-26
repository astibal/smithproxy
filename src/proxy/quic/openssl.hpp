#ifndef SMITHPROXY_QUIC_OPENSSL_HPP
#define SMITHPROXY_QUIC_OPENSSL_HPP

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include <sys/socket.h>

#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "proxy/multiflow/multiflow.hpp"

#if OPENSSL_VERSION_NUMBER >= 0x30500000L && !defined(OPENSSL_NO_QUIC)
#define SMITHPROXY_OPENSSL_QUIC 1
#include <openssl/quic.h>
#else
#define SMITHPROXY_OPENSSL_QUIC 0
#endif

namespace sx::quic {

/** Address value copied out of an OpenSSL BIO, safe beyond callback lifetime. */
struct datagram_endpoint {
    sockaddr_storage address {};
    socklen_t size = 0;
    bool valid() const { return size != 0; }
};

#if SMITHPROXY_OPENSSL_QUIC
namespace detail {

/** The complete UDP tuple needed to return one transparent QUIC datagram. */
struct datagram_route {
    datagram_endpoint peer;
    datagram_endpoint local;
};

/**
 * Bounded Connection-ID routing table used between OpenSSL's datagram pair
 * and the shared transparent UDP socket.
 *
 * Long headers teach both source and destination CIDs. Short headers omit the
 * CID length, so lookup accepts a prefix only when every match resolves to the
 * same tuple. Empty, unknown, and ambiguous CIDs deliberately have no route;
 * callers must drop such asynchronous output instead of guessing a client.
 */
class datagram_route_table final {
public:
    explicit datagram_route_table(std::size_t maximum_routes = 4096)
        : maximum_routes_(maximum_routes) {}

    void remember(std::vector<std::uint8_t> const& connection_id,
                  datagram_route const& route);
    void learn(unsigned char const* data, std::size_t size,
               datagram_route const& route);
    std::optional<datagram_route> resolve(
        unsigned char const* data, std::size_t size) const;
    std::size_t size() const { return routes_.size(); }

private:
    std::size_t maximum_routes_;
    std::map<std::vector<std::uint8_t>, datagram_route> routes_;
    std::deque<std::vector<std::uint8_t>> insertion_order_;
};

} // namespace detail
#endif

/** Observes the peer and original local destination of an incoming datagram. */
using datagram_observer = std::function<void(datagram_endpoint const& peer,
                                              datagram_endpoint const& local)>;
/** Copy an OpenSSL BIO_ADDR into the transport-neutral endpoint value. */
datagram_endpoint endpoint_from_bio_address(const BIO_ADDR* address);

constexpr bool openssl_quic_available() {
    return SMITHPROXY_OPENSSL_QUIC != 0;
}

/** Consume the current thread's OpenSSL error queue into a readable string. */
std::string openssl_error_stack();

struct ssl_deleter {
    void operator()(SSL* value) const { SSL_free(value); }
};

struct ssl_ctx_deleter {
    void operator()(SSL_CTX* value) const { SSL_CTX_free(value); }
};

using unique_ssl = std::unique_ptr<SSL, ssl_deleter>;
using unique_ssl_ctx = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;

/** Create a QUIC client/server context, or nullptr when unsupported. */
unique_ssl_ctx make_openssl_quic_context(bool server);

#if SMITHPROXY_OPENSSL_QUIC

/**
 * Multiflow adapter for one accepted or connected OpenSSL QUIC connection.
 * It assumes single-thread worker affinity, as required by the initial MF
 * design. The adapter owns the connection and every exposed stream SSL object.
 */
class openssl_connection final : public multiflow::connection {
public:
    /** Take ownership of a QUIC connection SSL and, optionally, its UDP fd. */
    explicit openssl_connection(unique_ssl connection, int owned_udp_fd = -1);
    ~openssl_connection() override;

    openssl_connection(openssl_connection const&) = delete;
    openssl_connection& operator=(openssl_connection const&) = delete;

    multiflow::flow_handle open_flow(multiflow::direction flow_direction) override;
    bool contains(multiflow::flow_handle flow) const override;
    std::optional<multiflow::direction> direction_of(multiflow::flow_handle flow) const override;
    multiflow::outer_transport policy_transport() const override {
        return multiflow::outer_transport::udp;
    }
    /** Map the internal generation-safe handle to the real QUIC stream ID. */
    std::optional<multiflow::flow_id> wire_flow_id(
        multiflow::flow_handle flow) const override;

    multiflow::io_result read(multiflow::flow_handle flow, void* destination,
                              std::size_t size) override;
    multiflow::io_result write(multiflow::flow_handle flow, const void* source,
                               std::size_t size) override;

    multiflow::io_status finish(multiflow::flow_handle flow) override;
    multiflow::io_status reset(multiflow::flow_handle flow,
                               std::uint64_t protocol_error) override;
    void close(std::uint64_t protocol_error = 0) override;

    bool readable(multiflow::flow_handle flow) const override;
    bool writable(multiflow::flow_handle flow) const override;
    /** Advance handshake/shutdown/timers without consuming queued flow events. */
    void progress_transport();
    /** Progress TLS, QUIC timers, stream acceptance, and lifecycle events. */
    std::vector<multiflow::event> drain_events() override;

    /** Feed a datagram after an external CID demultiplexer selected this connection. */
    bool inject_datagram(const unsigned char* data, std::size_t size,
                         const BIO_ADDR* peer, const BIO_ADDR* local);

    SSL* native_handle() const { return connection_.get(); } ///< Borrowed OpenSSL handle.
    /** Return the current datagram peer copied from the connection BIO. */
    datagram_endpoint peer_endpoint() const;
    /** True once TLS 1.3 authentication and QUIC parameter exchange complete. */
    bool handshake_complete() const;
    /** True once local or remote connection shutdown has begun. */
    bool closed() const { return closing_ || closed_; }
    /** SNI presented by the client or configured for an outgoing connection. */
    std::string server_name() const;
    /** Negotiated ALPN, or an empty string before/without negotiation. */
    std::string negotiated_alpn() const;

private:
    /** Owns the OpenSSL stream object and terminal-event suppression state. */
    struct stream_state;
    /** Coalescing key: at most one event of each type per flow is pending. */
    struct event_key {
        multiflow::event_type type;
        multiflow::flow_id id;

        friend bool operator<(event_key const& lhs, event_key const& rhs) {
            if (lhs.id != rhs.id) return lhs.id < rhs.id;
            return lhs.type < rhs.type;
        }
    };

    /** Resolve a handle only if both its ID and generation still match. */
    stream_state* find(multiflow::flow_handle flow);
    stream_state const* find(multiflow::flow_handle flow) const;
    /** Register an OpenSSL stream and publish its flow_open event. */
    multiflow::flow_handle attach_stream(unique_ssl stream, bool incoming);
    /** Query one stream through OpenSSL's zero-timeout polling API. */
    bool poll_stream(stream_state const& stream, std::uint64_t events) const;
    /** Queue a de-duplicated event for the next drain_events() call. */
    void emit(multiflow::event_type type,
              std::optional<multiflow::flow_handle> flow,
              std::uint64_t protocol_error = 0);

    unique_ssl connection_;                     ///< Owned OpenSSL QUIC connection.
    int owned_udp_fd_ = -1;                     ///< Outgoing socket, or -1 for listener-owned.
    std::map<multiflow::flow_id, std::unique_ptr<stream_state>> streams_; ///< Live streams.
    std::map<event_key, multiflow::event> events_; ///< Pending coalesced notifications.
    multiflow::flow_id next_internal_id_ = 1;
    multiflow::generation_id next_generation_ = 1;
    bool closing_ = false;                      ///< Nonblocking shutdown needs progress.
    bool closed_ = false;                       ///< Transport reached terminal state.
};

/**
 * Create a nonblocking outgoing QUIC connection over a newly owned UDP socket.
 * The returned adapter progresses its handshake from drain_events().
 */
std::unique_ptr<openssl_connection> connect_openssl_quic(
    SSL_CTX* context, const sockaddr* peer, socklen_t peer_size,
    std::string const& server_name, std::string* error = nullptr);
/** Same connector with an explicit single-protocol ALPN offer. */
std::unique_ptr<openssl_connection> connect_openssl_quic(
    SSL_CTX* context, const sockaddr* peer, socklen_t peer_size,
    std::string const& server_name, std::string const& alpn,
    std::string* error = nullptr);

/**
 * Nonblocking OpenSSL QUIC listener over a caller-owned UDP socket.
 *
 * The socket stays owned by the caller. When requested and supported by the
 * platform, its datagram BIO carries the local destination address on receive
 * and uses it as the source address on send. This is required by TPROXY.
 */
class openssl_listener final {
public:
    /** Internal state whose lifetime must cover the BIO receive callback. */
    struct observer_state;
    /** Socket/BIO queues used by the transparent datagram dispatcher. */
    struct dispatcher_state;
    /**
     * Attach a nonblocking OpenSSL QUIC listener to a caller-owned UDP socket.
     * enable_local_address requests destination-address metadata for transparent
     * replies; observer receives copied metadata before OpenSSL consumes it.
     */
    static std::unique_ptr<openssl_listener> create(SSL_CTX* context, int udp_fd,
                                                     bool enable_local_address = true,
                                                     datagram_observer observer = {});

    ~openssl_listener();
    openssl_listener(openssl_listener const&) = delete;
    openssl_listener& operator=(openssl_listener const&) = delete;

    /** Dequeue one connection whose OpenSSL listener handshake made it visible. */
    std::unique_ptr<openssl_connection> accept();
    /** Progress listener packet processing and QUIC timers without blocking. */
    bool handle_events();
    /** Flush output synchronously produced while servicing one known connection. */
    bool flush_output(datagram_endpoint const& peer, datagram_endpoint const& local);
    /** Socket readiness required by the dispatcher/direct network BIO. */
    short desired_socket_events() const;
    /** Diagnostic for the most recent adapter-level event failure. */
    std::string const& last_error() const { return last_error_; }
    /** Tuple of the datagram currently/most recently dispatched to OpenSSL. */
    datagram_endpoint current_peer() const;
    datagram_endpoint current_local() const;
    bool local_address_enabled() const { return local_address_enabled_; }
    SSL* native_handle() const { return listener_.get(); }

private:
    openssl_listener(std::unique_ptr<observer_state> observer,
                     std::unique_ptr<dispatcher_state> dispatcher, unique_ssl listener,
                     bool local_address_enabled);

    /** Store an adapter error together with the current OpenSSL error queue. */
    bool fail_operation(std::string operation);
    /** Move already-produced datagrams from the queue to the UDP socket. */
    bool flush_dispatcher_socket();
    /** Inject and fully service the oldest queued input datagram. */
    bool progress_input_packet();
    /** Read one bounded socket batch so other worker work cannot starve. */
    bool receive_input_batch();
    /** Advance timer-generated listener work after the readable batch. */
    bool progress_listener_timers();

    std::unique_ptr<observer_state> observer_state_; ///< Storage referenced by BIO callback.
    std::unique_ptr<dispatcher_state> dispatcher_state_; ///< Transparent socket pump state.
    unique_ssl listener_;                            ///< Owned OpenSSL listener object.
    bool local_address_enabled_ = false;             ///< BIO supports local-address metadata.
    std::string last_error_;                         ///< Socket/BIO pump failure detail.
};

#endif // SMITHPROXY_OPENSSL_QUIC

} // namespace sx::quic

#endif // SMITHPROXY_QUIC_OPENSSL_HPP
