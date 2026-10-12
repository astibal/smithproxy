#ifndef SMITHPROXY_QUICSERVICE_HPP
#define SMITHPROXY_QUICSERVICE_HPP

#include "proxy/quic/openssl.hpp"
#include "proxy/multiflow/mfmitmproxy.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace sx::quic {

namespace detail {
/** Internal guard against allocator reuse of a borrowed OpenSSL handle. */
bool same_certificate_callback_identity(std::string const& staged_server_name,
                                        std::uint64_t staged_generation,
                                        std::string const& current_server_name,
                                        std::uint64_t current_generation);
/** True only when callback re-entry still belongs to the same live QUIC tuple. */
bool same_dispatcher_callback_association(std::uint64_t staged_association,
                                          std::uint64_t current_association);
}

using flow_proxy_factory = std::function<std::unique_ptr<multiflow::flow_proxy>(
    std::shared_ptr<multiflow::connection>, std::shared_ptr<multiflow::connection>,
    multiflow::proxy_limits, multiflow::flow_proxy_context)>;

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
    std::size_t max_pending_capture_sessions = 64; ///< Unaccepted CID journals.
    std::size_t native_capture_buffer_bytes = 512 * 1024; ///< Before policy installs a logger.
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
};

/** Value-only session data published for management-plane diagnostics. */
struct session_snapshot {
    std::uint64_t id = 0;              ///< Listener-local monotonic identifier.
    std::string state;                 ///< handshake, active, or draining.
    std::string client;                ///< Numeric downstream endpoint, when exposed.
    std::string target;                ///< Original or configured upstream endpoint.
    std::string server_name;           ///< SNI presented by the downstream client.
    std::string downstream_alpn;       ///< Protocol negotiated with the client.
    std::string upstream_alpn;         ///< Protocol negotiated with the origin.
    std::uint64_t age_ms = 0;          ///< Milliseconds since the session was accepted.
    std::uint64_t idle_ms = 0;         ///< Milliseconds since bytes were last forwarded.
    std::uint64_t forwarded_bytes = 0; ///< Bytes moved across all paired streams.
    std::size_t streams = 0;           ///< Currently paired logical streams.
    std::size_t queued_bytes = 0;       ///< Bytes held due to stream backpressure.
    std::size_t stream_limit_rejections = 0; ///< Streams refused by the resource limit.
};

/**
 * Daemon-facing transparent QUIC MITM service.
 *
 * One instance owns one UDP listener and one worker-affine session loop. For a
 * verified production handshake it recovers the original destination, verifies
 * the real origin certificate against SNI in a bounded asynchronous job, and
 * only then installs a Smithproxy-derived downstream certificate. Established
 * downstream/upstream connections are joined by the configured flow-proxy
 * factory. The daemon installs a MitmProxy-per-stream implementation, while
 * isolated protocol tests may use the direct MFProxy bridge. The class owns
 * connection lifecycle; callers only prepare, run, stop, and read metrics.
 */
class listener_service final {
public:
    /** Configure the listener without opening sockets or starting its loop. */
    listener_service(std::uint16_t port, std::string certificate,
                     std::string private_key, bool transparent,
                     std::uint16_t upstream_port = 443,
                     bool verify_upstream = true,
                     lifecycle_options lifecycle = {},
                     resource_limits limits = {},
                     std::string upstream_host = {},
                     flow_proxy_factory proxy_factory = {},
                     bool capture_native = false);
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
    /** Return a copy without exposing worker-affine OpenSSL/MF objects. */
    std::vector<session_snapshot> session_diagnostics() const;

private:
    /** Create, configure, and bind the nonblocking UDP listener socket. */
    bool open_socket();
#if SMITHPROXY_OPENSSL_QUIC
    /** Test/non-transparent connector which resolves SNI as a host name. */
    std::shared_ptr<openssl_connection> connect_upstream(std::string const& host);
    /** Production connector to the captured original destination. */
    std::shared_ptr<openssl_connection> connect_upstream(
        datagram_endpoint const& target, std::string const& server_name);
    /** OpenSSL trampoline; return -1 while asynchronous preparation is pending. */
    static int certificate_callback(SSL* ssl, void* argument);
    /** Bind a newly parsed ClientHello to the dispatcher's stable CID family. */
    static int client_hello_callback(SSL* ssl, int* alert, void* argument);
    int bind_capture_session(SSL* downstream);
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
    std::string upstream_host_;                  ///< Optional explicit non-transparent target.
    bool verify_upstream_;                       ///< Require origin-backed certificate creation.
    lifecycle_options lifecycle_;                ///< Session timing policy.
    resource_limits limits_;                     ///< Resource-exhaustion policy.
    flow_proxy_factory proxy_factory_;           ///< Production per-stream proxy strategy.
    bool capture_native_;                        ///< Buffer downstream wire records for policy.
    int udp_fd_ = -1;                            ///< Socket owned by this service.
    int wake_fd_ = -1;                           ///< eventfd used to interrupt an idle poll.
    std::atomic_bool stopping_ = false;           ///< Cross-thread stop request.
    std::atomic_size_t connection_count_ = 0;     ///< Sessions currently retained by the loop.
    mutable std::mutex snapshots_mutex_;          ///< Protects only copied diagnostics.
    std::vector<session_snapshot> snapshots_;     ///< Last worker-published view.
    std::uint64_t next_session_id_ = 1;           ///< Worker-owned diagnostic ID source.

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
        std::uint64_t id = 0;
        session_state state = session_state::handshake;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point last_activity = created;
        std::chrono::steady_clock::time_point draining_since {};
        std::shared_ptr<openssl_connection> downstream;
        std::shared_ptr<openssl_connection> upstream;
        std::shared_ptr<keylog_store> keylog; ///< Downstream secrets for capture export.
        std::shared_ptr<sx::session_traffic_log> capture_log; ///< Policy-bound wire journal.
        std::uint64_t capture_association = 0; ///< Downstream dispatcher CID family.
        std::size_t keylog_cursor = 0; ///< Number of keylog records already published.
        std::unique_ptr<multiflow::flow_proxy> proxy;
        datagram_endpoint client_endpoint;
        datagram_endpoint target_endpoint;
        std::uint64_t forwarded_bytes = 0;
        std::size_t reported_stream_limit_rejections = 0; ///< Counter delta cursor.
    };
    std::vector<session> sessions_;              ///< Worker-owned live/draining sessions.
    /** Verified route waiting for OpenSSL to expose its downstream connection. */
    struct staged_upstream {
        datagram_endpoint client;
        datagram_endpoint destination;
        std::string server_name;
        std::uint64_t callback_generation = 0;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
    };
    std::map<SSL*, staged_upstream> staged_upstreams_; ///< Key is borrowed downstream SSL.
    /** Immutable certificate material transferred from a certificate worker. */
    struct verified_certificate {
        std::shared_ptr<X509> certificate;
        std::shared_ptr<EVP_PKEY> private_key;
    };
    /** Future and creation time for one suspended OpenSSL certificate callback. */
    struct certificate_job {
        std::future<verified_certificate> result;
        datagram_endpoint client;
        datagram_endpoint destination;
        std::string server_name;
        std::uint64_t callback_generation = 0;
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
    };
    std::map<SSL*, certificate_job> certificate_jobs_; ///< Bounded pending verifications.
    /** Wire journal created by an Initial before OpenSSL publishes its session. */
    struct pending_capture {
        std::shared_ptr<sx::session_traffic_log> log;
        std::chrono::steady_clock::time_point updated = std::chrono::steady_clock::now();
    };
    std::map<std::uint64_t, pending_capture> pending_captures_; ///< CID family -> journal.
    std::map<std::uint64_t, std::weak_ptr<sx::session_traffic_log>> capture_routes_;
    struct dispatcher_binding {
        std::uint64_t association = 0;
        std::uint64_t generation = 0;
        std::chrono::steady_clock::time_point updated = std::chrono::steady_clock::now();
    };
    std::map<SSL*, dispatcher_binding> dispatcher_bindings_; ///< ClientHello until accept.
    std::uint64_t next_dispatcher_binding_generation_ = 1;

    /** Transfer certificate-worker results to the matching accepted session. */
    void attach_staged_upstream(session& value);
    /** Record one downstream datagram without exposing QUIC to the logger API. */
    void observe_datagram(datagram_view const& datagram);
    /** Publish keylog records added since the previous session-loop pass. */
    void publish_capture_secrets(session& value);
    /** Accept every connection currently available without blocking the worker. */
    void accept_connections();
    /** Progress one session according to its explicit lifecycle state. */
    void progress_session(session& value, std::chrono::steady_clock::time_point now);
    /** Complete both handshakes and construct the per-stream proxy bridge. */
    void progress_handshake(session& value, std::chrono::steady_clock::time_point now);
    /** Pump established streams and enforce the session idle timeout. */
    void progress_active(session& value, std::chrono::steady_clock::time_point now);
    /** Flush OpenSSL output with this session's unambiguous UDP tuple. */
    bool flush_session_output(session& value);
    /** Release expired draining sessions and abandoned staged upstream legs. */
    void reap_expired(std::chrono::steady_clock::time_point now);
    /** Stop proxying and begin bounded nonblocking shutdown of both legs. */
    void start_draining(session& value, std::chrono::steady_clock::time_point now,
                        std::uint64_t protocol_error = 0);
    /** Close and release all session/job state when the worker exits. */
    void cleanup_sessions();
    /** Replace the CLI-visible value copy from the worker-owned live state. */
    void publish_session_snapshots(std::chrono::steady_clock::time_point now);
#endif
};

} // namespace sx::quic

#endif
