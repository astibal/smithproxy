#ifndef SMITHPROXY_QUICSERVICE_HPP
#define SMITHPROXY_QUICSERVICE_HPP

#include "proxy/quic/openssl.hpp"
#include "proxy/multiflow/mfproxy.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <map>
#include <string>
#include <vector>

namespace sx::quic {

/** Time bounds for each externally observable session lifecycle phase. */
struct lifecycle_options {
    std::chrono::milliseconds handshake_timeout { std::chrono::seconds(10) }; ///< Both legs.
    std::chrono::milliseconds idle_timeout { std::chrono::minutes(5) }; ///< No forwarded bytes.
    std::chrono::milliseconds drain_timeout { std::chrono::seconds(3) }; ///< Shutdown grace.
};

/** Hard per-listener/per-session bounds that fail closed when exhausted. */
struct resource_limits {
    std::size_t max_sessions = 4096;              ///< Includes draining sessions.
    std::size_t max_streams_per_session = 256;    ///< Simultaneously paired flows.
    std::size_t stream_buffer_bytes = 16 * 1024;  ///< Per flow and direction.
    std::size_t max_certificate_jobs = 64;        ///< Concurrent origin verification jobs.
};

/** Lock-free copy of cumulative listener counters for logs/metrics/tests. */
struct diagnostics_snapshot {
    std::size_t current_sessions = 0;
    std::uint64_t accepted_sessions = 0;
    std::uint64_t completed_sessions = 0;
    std::uint64_t handshake_timeouts = 0;
    std::uint64_t handshake_failures = 0;
    std::uint64_t idle_timeouts = 0;
    std::uint64_t upstream_failures = 0;
    std::uint64_t alpn_failures = 0;
    std::uint64_t session_limit_rejections = 0;
    std::uint64_t stream_limit_rejections = 0;
    std::uint64_t certificate_job_limit_rejections = 0;
    std::uint64_t discarded_non_quic_datagrams = 0;
};

/**
 * Daemon-facing transparent QUIC MITM service.
 *
 * One instance owns one UDP listener and one worker-affine session loop. For a
 * verified production handshake it recovers the original destination, verifies
 * the real origin certificate against SNI in a bounded asynchronous job, and
 * only then installs a Smithproxy-derived downstream certificate. Established
 * downstream/upstream connections are joined by MFProxy. The class deliberately
 * owns connection lifecycle; callers only prepare, run, stop, and read metrics.
 */
class listener_service final {
public:
    /** Configure the listener without opening sockets or starting its loop. */
    listener_service(std::uint16_t port, std::string certificate,
                     std::string private_key, bool transparent,
                     std::uint16_t upstream_port = 443,
                     bool verify_upstream = true,
                     lifecycle_options lifecycle = {},
                     resource_limits limits = {});
    ~listener_service();

    listener_service(listener_service const&) = delete;
    listener_service& operator=(listener_service const&) = delete;

    /** Allocate contexts/socket/listener. Safe to call again after success. */
    bool prepare();
    /** Run the single-thread event loop until stop() or a fatal listener error. */
    void run();
    /** Request loop termination; cleanup occurs in run() before it returns. */
    void stop();

    bool ready() const { return ready_; }
    std::uint16_t bound_port() const { return bound_port_; }
    std::string const& last_error() const { return last_error_; }
    std::size_t connection_count() const { return connection_count_; }
    /** Atomically sample operational counters without touching session state. */
    diagnostics_snapshot diagnostics() const;

private:
    /** Create, configure, and bind the nonblocking UDP listener socket. */
    bool open_socket();
#if SMITHPROXY_OPENSSL_QUIC
    /** Discard non-QUIC datagrams and report whether OpenSSL may read the queue. */
    bool discard_non_quic_datagrams(bool& safe_for_openssl);
    /** Test/non-transparent connector which resolves SNI as a host name. */
    std::shared_ptr<openssl_connection> connect_upstream(std::string const& host);
    /** Production connector to the captured original destination. */
    std::shared_ptr<openssl_connection> connect_upstream(
        datagram_endpoint const& target, std::string const& server_name);
    /** OpenSSL trampoline; return -1 while asynchronous preparation is pending. */
    static int certificate_callback(SSL* ssl, void* argument);
    /** Start or collect one origin-verification job for a downstream handshake. */
    int prepare_verified_certificate(SSL* downstream);
    struct verified_certificate;
    /** Worker-thread operation: connect, verify identity, and derive a certificate. */
    verified_certificate verify_and_spoof(datagram_endpoint destination,
                                           std::string server_name);
    /** Install already-owned key material back on the listener thread. */
    bool install_verified_certificate(SSL* downstream,
                                      verified_certificate const& verified);
#endif
    /** Record a fatal listener error and make ready() false. */
    void fail(std::string message);

    std::uint16_t port_;                         ///< Requested local service port.
    std::uint16_t bound_port_ = 0;               ///< Actual port, relevant when port_ is zero.
    std::string certificate_;                    ///< Bootstrap/default certificate chain.
    std::string private_key_;                    ///< Bootstrap/default private key.
    bool transparent_;                           ///< Enable Linux transparent metadata/options.
    std::uint16_t upstream_port_;                ///< Non-transparent test fallback port.
    bool verify_upstream_;                       ///< Require origin-backed certificate creation.
    lifecycle_options lifecycle_;                ///< Session timing policy.
    resource_limits limits_;                     ///< Resource-exhaustion policy.
    int udp_fd_ = -1;                            ///< Socket owned by this service.
    std::atomic_bool stopping_ = false;           ///< Cross-thread stop request.
    std::atomic_size_t connection_count_ = 0;     ///< Sessions currently retained by the loop.

    // Monotonic atomics back diagnostics(); writers live in the worker except
    // for certificate results, while readers may sample from management code.
    std::atomic_uint64_t accepted_sessions_ = 0;
    std::atomic_uint64_t completed_sessions_ = 0;
    std::atomic_uint64_t handshake_timeouts_ = 0;
    std::atomic_uint64_t handshake_failures_ = 0;
    std::atomic_uint64_t idle_timeouts_ = 0;
    std::atomic_uint64_t upstream_failures_ = 0;
    std::atomic_uint64_t alpn_failures_ = 0;
    std::atomic_uint64_t session_limit_rejections_ = 0;
    std::atomic_uint64_t stream_limit_rejections_ = 0;
    std::atomic_uint64_t certificate_job_limit_rejections_ = 0;
    std::atomic_uint64_t discarded_non_quic_datagrams_ = 0;
    bool ready_ = false;                         ///< prepare() completed successfully.
    std::string last_error_;                     ///< Fatal setup/event-loop diagnostic.

#if SMITHPROXY_OPENSSL_QUIC
    unique_ssl_ctx context_;                     ///< Downstream QUIC server context.
    unique_ssl_ctx client_context_;              ///< Verified upstream QUIC client context.
    std::unique_ptr<openssl_listener> listener_; ///< Adapter over udp_fd_.
    /** Session phases are explicit so shutdown resources remain bounded. */
    enum class session_state { handshake, active, draining };
    /** All state owned by one downstream/upstream connection pair. */
    struct session {
        session_state state = session_state::handshake;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point last_activity = created;
        std::chrono::steady_clock::time_point draining_since {};
        std::shared_ptr<openssl_connection> downstream;
        std::shared_ptr<openssl_connection> upstream;
        std::unique_ptr<multiflow::MFProxy> proxy;
        std::size_t reported_stream_limit_rejections = 0; ///< Counter delta cursor.
    };
    std::vector<session> sessions_;              ///< Worker-owned live/draining sessions.
    /** Verified upstream waiting for OpenSSL to expose its downstream connection. */
    struct staged_upstream {
        std::shared_ptr<openssl_connection> connection;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
    };
    std::map<SSL*, staged_upstream> staged_upstreams_; ///< Key is borrowed downstream SSL.
    /** Reference-counted output transferred safely from a certificate worker. */
    struct verified_certificate {
        std::shared_ptr<openssl_connection> connection;
        std::shared_ptr<X509> certificate;
        std::shared_ptr<EVP_PKEY> private_key;
    };
    /** Future and creation time for one suspended OpenSSL certificate callback. */
    struct certificate_job {
        std::future<verified_certificate> result;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
    };
    std::map<SSL*, certificate_job> certificate_jobs_; ///< Bounded pending verifications.
    std::map<std::string, datagram_endpoint> original_destinations_; ///< Peer -> TPROXY target.
    /** Stop proxying and begin bounded nonblocking shutdown of both legs. */
    void start_draining(session& value, std::chrono::steady_clock::time_point now,
                        std::uint64_t protocol_error = 0);
    /** Close and release all session/job state when the worker exits. */
    void cleanup_sessions();
#endif
};

} // namespace sx::quic

#endif
