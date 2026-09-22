#ifndef SMITHPROXY_QUIC_OPENSSL_HPP
#define SMITHPROXY_QUIC_OPENSSL_HPP

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include <sys/socket.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <functional>

#include "proxy/multiflow/multiflow.hpp"

#if OPENSSL_VERSION_NUMBER >= 0x30500000L && !defined(OPENSSL_NO_QUIC)
#define SMITHPROXY_OPENSSL_QUIC 1
#include <openssl/quic.h>
#else
#define SMITHPROXY_OPENSSL_QUIC 0
#endif

namespace sx::quic {

struct datagram_endpoint {
    sockaddr_storage address {};
    socklen_t size = 0;
    bool valid() const { return size != 0; }
};

using datagram_observer = std::function<void(datagram_endpoint const& peer,
                                              datagram_endpoint const& local)>;
datagram_endpoint endpoint_from_bio_address(const BIO_ADDR* address);

constexpr bool openssl_quic_available() {
    return SMITHPROXY_OPENSSL_QUIC != 0;
}

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
    explicit openssl_connection(unique_ssl connection, int owned_udp_fd = -1);
    ~openssl_connection() override;

    openssl_connection(openssl_connection const&) = delete;
    openssl_connection& operator=(openssl_connection const&) = delete;

    multiflow::flow_handle open_flow(multiflow::direction flow_direction) override;
    bool contains(multiflow::flow_handle flow) const override;
    std::optional<multiflow::direction> direction_of(multiflow::flow_handle flow) const override;

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
    std::vector<multiflow::event> drain_events() override;

    /** Feed a datagram after an external CID demultiplexer selected this connection. */
    bool inject_datagram(const unsigned char* data, std::size_t size,
                         const BIO_ADDR* peer, const BIO_ADDR* local);

    SSL* native_handle() const { return connection_.get(); }
    datagram_endpoint peer_endpoint() const;
    bool handshake_complete() const;
    bool closed() const { return closing_ || closed_; }
    std::string server_name() const;

private:
    struct stream_state;
    struct event_key {
        multiflow::event_type type;
        multiflow::flow_id id;

        friend bool operator<(event_key const& lhs, event_key const& rhs) {
            if (lhs.id != rhs.id) return lhs.id < rhs.id;
            return lhs.type < rhs.type;
        }
    };

    stream_state* find(multiflow::flow_handle flow);
    stream_state const* find(multiflow::flow_handle flow) const;
    multiflow::flow_handle attach_stream(unique_ssl stream, bool incoming);
    bool poll_stream(stream_state const& stream, std::uint64_t events) const;
    void emit(multiflow::event_type type,
              std::optional<multiflow::flow_handle> flow,
              std::uint64_t protocol_error = 0);

    unique_ssl connection_;
    int owned_udp_fd_ = -1;
    std::map<multiflow::flow_id, std::unique_ptr<stream_state>> streams_;
    std::map<event_key, multiflow::event> events_;
    multiflow::flow_id next_internal_id_ = 1;
    multiflow::generation_id next_generation_ = 1;
    bool closing_ = false;
    bool closed_ = false;
};

/**
 * Create a nonblocking outgoing QUIC connection over a newly owned UDP socket.
 * The returned adapter progresses its handshake from drain_events().
 */
std::unique_ptr<openssl_connection> connect_openssl_quic(
    SSL_CTX* context, const sockaddr* peer, socklen_t peer_size,
    std::string const& server_name, std::string* error = nullptr);

/**
 * Nonblocking OpenSSL QUIC listener over a caller-owned UDP socket.
 *
 * The socket stays owned by the caller. When requested and supported by the
 * platform, its datagram BIO carries the local destination address on receive
 * and uses it as the source address on send. This is required by TPROXY.
 */
class openssl_listener final {
public:
    struct observer_state;
    static std::unique_ptr<openssl_listener> create(SSL_CTX* context, int udp_fd,
                                                     bool enable_local_address = true,
                                                     datagram_observer observer = {});

    ~openssl_listener();
    openssl_listener(openssl_listener const&) = delete;
    openssl_listener& operator=(openssl_listener const&) = delete;

    std::unique_ptr<openssl_connection> accept();
    bool handle_events();
    bool local_address_enabled() const { return local_address_enabled_; }
    SSL* native_handle() const { return listener_.get(); }

private:
    openssl_listener(std::unique_ptr<observer_state> state, unique_ssl listener,
                     bool local_address_enabled);

    std::unique_ptr<observer_state> observer_state_;
    unique_ssl listener_;
    bool local_address_enabled_ = false;
};

#endif // SMITHPROXY_OPENSSL_QUIC

} // namespace sx::quic

#endif // SMITHPROXY_QUIC_OPENSSL_HPP
