#include "service/quic/quicservice.hpp"
#include "service/quic/quiclog.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <thread>
#include <utility>

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sslcertstore.hpp>
#include <sslmitmcom.hpp>
#endif

namespace sx::quic {

namespace {

#if SMITHPROXY_OPENSSL_QUIC
int select_h3(SSL*, const unsigned char** output, unsigned char* output_size,
              const unsigned char* input, unsigned input_size, void*) {
    static constexpr unsigned char supported[] = { 2, 'h', '3' };
    return SSL_select_next_proto(const_cast<unsigned char**>(output), output_size,
                                 supported, sizeof(supported), input, input_size)
            == OPENSSL_NPN_NEGOTIATED
        ? SSL_TLSEXT_ERR_OK
        : SSL_TLSEXT_ERR_ALERT_FATAL;
}

std::string endpoint_key(datagram_endpoint const& endpoint) {
    if (!endpoint.valid()) return {};
    auto const* begin = reinterpret_cast<char const*>(&endpoint.address);
    return std::string(begin, begin + endpoint.size);
}

std::string endpoint_text(datagram_endpoint const& endpoint) {
    if (!endpoint.valid()) return "-";
    char host[NI_MAXHOST] {};
    char service[NI_MAXSERV] {};
    if (::getnameinfo(reinterpret_cast<sockaddr const*>(&endpoint.address), endpoint.size,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST | NI_NUMERICSERV) != 0) return "?";
    bool const ipv6 = endpoint.address.ss_family == AF_INET6;
    return std::string(ipv6 ? "[" : "") + host + (ipv6 ? "]:" : ":") + service;
}

std::pair<std::string, std::string> endpoint_parts(datagram_endpoint const& endpoint) {
    if (!endpoint.valid()) return {};
    char host[NI_MAXHOST] {};
    char service[NI_MAXSERV] {};
    if (::getnameinfo(reinterpret_cast<sockaddr const*>(&endpoint.address), endpoint.size,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST | NI_NUMERICSERV) != 0) return {};
    return {host, service};
}

int listener_poll_timeout(SSL* listener, int application_timeout_ms) {
    timeval timeout {};
    int infinite = 1;
    if (!listener || SSL_get_event_timeout(listener, &timeout, &infinite) != 1
        || infinite) {
        return application_timeout_ms;
    }
    auto const seconds = static_cast<long long>(timeout.tv_sec);
    auto const microseconds = static_cast<long long>(timeout.tv_usec);
    auto const openssl_timeout = seconds >= INT_MAX / 1000
        ? INT_MAX
        : static_cast<int>(std::min<long long>(
              INT_MAX, seconds * 1000 + (microseconds + 999) / 1000));
    return application_timeout_ms < 0
        ? openssl_timeout : std::min(application_timeout_ms, openssl_timeout);
}
#endif

} // namespace

listener_service::listener_service(std::uint16_t port, std::string certificate,
                                   std::string private_key, bool transparent,
                                   std::uint16_t upstream_port, bool verify_upstream,
                                   lifecycle_options lifecycle, resource_limits limits,
                                   std::string upstream_host,
                                   flow_proxy_factory proxy_factory)
    : port_(port), certificate_(std::move(certificate)),
      private_key_(std::move(private_key)), transparent_(transparent),
      upstream_port_(upstream_port), upstream_host_(std::move(upstream_host)),
      verify_upstream_(verify_upstream), lifecycle_(lifecycle), limits_(limits),
      proxy_factory_(std::move(proxy_factory)) {
    (void)log();
}

diagnostics_snapshot listener_service::diagnostics() const {
    return {
        connection_count_.load(), accepted_sessions_.load(), completed_sessions_.load(),
        handshake_timeouts_.load(), handshake_failures_.load(), idle_timeouts_.load(),
        upstream_failures_.load(), alpn_failures_.load(),
        session_limit_rejections_.load(), stream_limit_rejections_.load(),
        certificate_job_limit_rejections_.load()
    };
}

std::vector<session_snapshot> listener_service::session_diagnostics() const {
    std::lock_guard<std::mutex> lock(snapshots_mutex_);
    return snapshots_;
}

listener_service::~listener_service() {
    stop();
#if SMITHPROXY_OPENSSL_QUIC
    sessions_.clear();
    for (auto& job : certificate_jobs_) {
        try {
            auto result = job.second.result.get();
            if (result.connection) result.connection->close();
        } catch (...) {
        }
    }
    certificate_jobs_.clear();
    staged_upstreams_.clear();
    connection_count_ = 0;
    listener_.reset();
    context_.reset();
    if (udp_fd_ >= 0) ::close(udp_fd_);
    if (wake_fd_ >= 0) ::close(wake_fd_);
#endif
}

void listener_service::fail(std::string message) {
    last_error_ = std::move(message);
    ready_ = false;
    log().err("listener failure: %s", last_error_.c_str());
}

bool listener_service::open_socket() {
#if SMITHPROXY_OPENSSL_QUIC
    wake_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd_ < 0) {
        fail(std::string("eventfd: ") + std::strerror(errno));
        return false;
    }
    udp_fd_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd_ < 0) {
        fail(std::string("socket: ") + std::strerror(errno));
        return false;
    }

    int enabled = 1;
    if (::setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        fail(std::string("SO_REUSEADDR: ") + std::strerror(errno));
        return false;
    }
    if (transparent_
        && ::setsockopt(udp_fd_, SOL_IP, IP_TRANSPARENT, &enabled, sizeof(enabled)) != 0) {
        fail(std::string("IP_TRANSPARENT: ") + std::strerror(errno));
        return false;
    }
    if (transparent_
        && ::setsockopt(udp_fd_, SOL_IP, IP_RECVORIGDSTADDR,
                        &enabled, sizeof(enabled)) != 0) {
        fail(std::string("IP_RECVORIGDSTADDR: ") + std::strerror(errno));
        return false;
    }

    auto const flags = ::fcntl(udp_fd_, F_GETFL, 0);
    if (flags < 0 || ::fcntl(udp_fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
        fail(std::string("O_NONBLOCK: ") + std::strerror(errno));
        return false;
    }

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port_);
    if (::bind(udp_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        fail(std::string("bind: ") + std::strerror(errno));
        return false;
    }
    socklen_t address_size = sizeof(address);
    if (::getsockname(udp_fd_, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        fail(std::string("getsockname: ") + std::strerror(errno));
        return false;
    }
    bound_port_ = ntohs(address.sin_port);
    log().dia("socket ready on udp/*:%u transparent=%d", bound_port_, transparent_);
    return true;
#else
    fail("OpenSSL was built without QUIC server support (requires OpenSSL 3.5+)");
    return false;
#endif
}

bool listener_service::prepare() {
#if SMITHPROXY_OPENSSL_QUIC
    if (ready_) return true;
    stopping_ = false;
    context_ = make_openssl_quic_context(true);
    client_context_ = make_openssl_quic_context(false);
    if (!context_ || !client_context_) {
        fail("cannot create OpenSSL QUIC context: " + openssl_error_stack());
        return false;
    }
    if (SSL_CTX_use_certificate_chain_file(context_.get(), certificate_.c_str()) != 1
        || SSL_CTX_use_PrivateKey_file(context_.get(), private_key_.c_str(), SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(context_.get()) != 1) {
        fail("cannot load QUIC certificate/key: " + openssl_error_stack());
        return false;
    }
    SSL_CTX_set_alpn_select_cb(context_.get(), select_h3, nullptr);
    if (verify_upstream_) {
        if (!SSLFactory::factory().set_verify_locations(client_context_.get())) {
            fail("cannot load QUIC upstream trust store");
            return false;
        }
        SSL_CTX_set_verify(client_context_.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_cert_cb(context_.get(), certificate_callback, this);
    } else {
        SSL_CTX_set_verify(client_context_.get(), SSL_VERIFY_NONE, nullptr);
    }

    if (!open_socket()) return false;
    listener_ = openssl_listener::create(
        context_.get(), udp_fd_, transparent_,
        [this](datagram_endpoint const& peer, datagram_endpoint const& destination) {
            original_destinations_[endpoint_key(peer)] = destination;
            log().ext("datagram peer=%s original-destination=%s",
                      endpoint_text(peer).c_str(), endpoint_text(destination).c_str());
        });
    if (!listener_) {
        fail("cannot create OpenSSL QUIC listener: " + openssl_error_stack());
        return false;
    }
    ready_ = true;
    last_error_.clear();
    log().inf("listener ready on udp/*:%u verify-upstream=%d", bound_port_, verify_upstream_);
    return true;
#else
    return open_socket();
#endif
}

void listener_service::run() {
#if SMITHPROXY_OPENSSL_QUIC
    if (!ready_ && !prepare()) return;
    log().inf("listener loop started on udp/*:%u", bound_port_);

    pollfd descriptors[] {
        { udp_fd_, 0, 0 },
        { wake_fd_, POLLIN, 0 },
    };

    while (!stopping_) {
        // With no retained work, wait solely for network input or stop().
        // Active connections still need a bounded tick because OpenSSL QUIC
        // timers and asynchronous certificate futures are not pollable fds.
        auto const application_timeout = sessions_.empty() && certificate_jobs_.empty()
                && staged_upstreams_.empty()
            ? -1
            : 50;
        auto* native_listener = listener_->native_handle();
        descriptors[0].events = listener_->desired_socket_events();
        auto const timeout = listener_poll_timeout(native_listener, application_timeout);
        log().dum("poll events=0x%x timeout=%d sessions=%zu cert-jobs=%zu",
                  descriptors[0].events, timeout, sessions_.size(), certificate_jobs_.size());
        auto const polled = ::poll(descriptors, 2, timeout);
        if (polled < 0 && errno != EINTR) {
            fail(std::string("poll: ") + std::strerror(errno));
            break;
        }
        if (descriptors[1].revents & POLLIN) {
            eventfd_t wakeups = 0;
            while (::eventfd_read(wake_fd_, &wakeups) == 0) {
            }
        }
        if (descriptors[0].revents != 0) {
            log().dum("network wake revents=0x%x", descriptors[0].revents);
        }
        if (stopping_) break;

        // Do not pre-classify this shared UDP socket with MSG_PEEK. OpenSSL may
        // receive a batch after the peek, so a following DTLS datagram could
        // still cross that boundary and make the apparent demultiplexing racy.
        // Supporting QUIC and DTLS on one port requires a dispatcher which owns
        // recvmsg() and injects only classified QUIC datagrams into OpenSSL.
        if (!listener_->handle_events() && !stopping_) {
            auto detail = listener_->last_error();
            if (detail.empty()) detail = openssl_error_stack();
            fail("OpenSSL QUIC listener event failure: " + detail);
            break;
        }

        // Accept first, then advance every retained session exactly once.
        accept_connections();
        auto const now = std::chrono::steady_clock::now();
        for (auto& linked : sessions_) {
            progress_session(linked, now);
            if (!flush_session_output(linked)) {
                stopping_ = true;
                break;
            }
        }

        // Publish only after removing objects whose grace period has elapsed.
        reap_expired(now);
        publish_session_snapshots(now);
    }
    cleanup_sessions();
    log().inf("listener loop stopped on udp/*:%u", bound_port_);
#endif
}

#if SMITHPROXY_OPENSSL_QUIC
void listener_service::attach_staged_upstream(session& value) {
    if (!value.downstream || value.upstream) return;

    // The certificate callback knows the transparent tuple before OpenSSL
    // publishes the accepted connection object. Preserve it across that gap.
    auto* key = value.downstream->native_handle();
    if (auto pending = certificate_jobs_.find(key); pending != certificate_jobs_.end()) {
        value.client_endpoint = pending->second.client;
        value.target_endpoint = pending->second.destination;
    }

    auto found = staged_upstreams_.find(key);
    if (found == staged_upstreams_.end()) return;

    value.upstream = std::move(found->second.connection);
    if (!value.client_endpoint.valid()) value.client_endpoint = found->second.client;
    value.target_endpoint = found->second.destination;
    if (!value.target_endpoint.valid() && value.upstream) {
        value.target_endpoint = value.upstream->peer_endpoint();
    }
    staged_upstreams_.erase(found);
}

void listener_service::accept_connections() {
    while (auto accepted = listener_->accept()) {
        auto connection = std::shared_ptr<openssl_connection>(std::move(accepted));

        // Refuse excess work before allocating session/proxy state.
        if (sessions_.size() >= limits_.max_sessions) {
            ++session_limit_rejections_;
            log().war("session rejected: listener limit %zu reached", limits_.max_sessions);
            connection->close(0x107);
            continue;
        }

        session incoming;
        incoming.id = next_session_id_++;
        incoming.downstream = std::move(connection);
        incoming.client_endpoint = incoming.downstream->peer_endpoint();
        attach_staged_upstream(incoming);

        sessions_.push_back(std::move(incoming));
        ++connection_count_;
        ++accepted_sessions_;

        auto const& value = sessions_.back();
        log().inf("session %llu accepted from %s",
                  static_cast<unsigned long long>(value.id),
                  endpoint_text(value.client_endpoint).c_str());
    }
}

void listener_service::progress_session(
    session& value, std::chrono::steady_clock::time_point now) {
    switch (value.state) {
    case session_state::handshake:
        progress_handshake(value, now);
        break;
    case session_state::active:
        progress_active(value, now);
        break;
    case session_state::draining:
        // QUIC shutdown is nonblocking; both legs still need timer progress.
        if (value.downstream) value.downstream->drain_events();
        if (value.upstream) value.upstream->drain_events();
        break;
    }
}

void listener_service::progress_handshake(
    session& value, std::chrono::steady_clock::time_point now) {
    attach_staged_upstream(value);

    // Keep progressing ACKs, final handshake flight, and timers under this
    // session's tuple. progress_transport() deliberately does not dequeue
    // flow_open, so early application streams remain available to the bridge.
    value.downstream->progress_transport();

    if (value.downstream->closed()) {
        ++handshake_failures_;
        log().war("session %llu downstream handshake failed",
                  static_cast<unsigned long long>(value.id));
        start_draining(value, now);
        return;
    }
    if (now - value.created >= lifecycle_.handshake_timeout) {
        ++handshake_timeouts_;
        log().war("session %llu handshake timed out",
                  static_cast<unsigned long long>(value.id));
        start_draining(value, now);
        return;
    }

    // Tests may skip origin verification; production receives its upstream
    // connection from the certificate job above.
    if (!verify_upstream_ && value.downstream->handshake_complete() && !value.upstream) {
        value.upstream = connect_upstream(value.downstream->server_name());
        if (!value.upstream) {
            ++upstream_failures_;
            log().war("session %llu cannot create upstream connection",
                      static_cast<unsigned long long>(value.id));
            start_draining(value, now);
        }
        return;
    }
    if (!value.upstream) return;

    value.upstream->drain_events();
    if (value.upstream->closed()) {
        ++upstream_failures_;
        log().war("session %llu upstream handshake failed",
                  static_cast<unsigned long long>(value.id));
        start_draining(value, now);
        return;
    }
    if (!value.upstream->handshake_complete()) return;

    // Both legs must agree on the application protocol before streams can be
    // paired. This prevents forwarding bytes between incompatible protocols.
    auto const downstream_alpn = value.downstream->negotiated_alpn();
    auto const upstream_alpn = value.upstream->negotiated_alpn();
    if (downstream_alpn.empty() || downstream_alpn != upstream_alpn) {
        ++alpn_failures_;
        log().war("session %llu ALPN mismatch downstream='%s' upstream='%s'",
                  static_cast<unsigned long long>(value.id),
                  downstream_alpn.c_str(), upstream_alpn.c_str());
        start_draining(value, now, 1);
        return;
    }

    auto const proxy_limits = multiflow::proxy_limits {
        limits_.max_streams_per_session,
        limits_.stream_buffer_bytes,
    };
    if (proxy_factory_) {
        auto [source_host, source_port] = endpoint_parts(value.client_endpoint);
        auto [target_host, target_port] = endpoint_parts(value.target_endpoint);
        value.proxy = proxy_factory_(
            value.downstream, value.upstream, proxy_limits,
            {std::move(source_host), std::move(source_port),
             std::move(target_host), std::move(target_port),
             value.target_endpoint.address.ss_family});
    } else {
        value.proxy = std::make_unique<multiflow::MFProxy>(
            value.downstream, value.upstream, proxy_limits);
    }
    if (!value.proxy) {
        ++upstream_failures_;
        start_draining(value, now);
        return;
    }

    value.state = session_state::active;
    value.last_activity = now;
    log().inf("session %llu active sni='%s' alpn='%s' target=%s",
              static_cast<unsigned long long>(value.id),
              value.downstream->server_name().c_str(),
              downstream_alpn.c_str(), endpoint_text(value.target_endpoint).c_str());
}

void listener_service::progress_active(
    session& value, std::chrono::steady_clock::time_point now) {
    auto const moved = value.proxy->pump_once();
    if (moved != 0) {
        value.last_activity = now;
        value.forwarded_bytes += moved;
    }

    // Convert the proxy-local cumulative counter into the service cumulative
    // counter without counting an old rejection more than once.
    auto const rejected = value.proxy->limit_rejections();
    if (rejected > value.reported_stream_limit_rejections) {
        stream_limit_rejections_ += rejected - value.reported_stream_limit_rejections;
        value.reported_stream_limit_rejections = rejected;
    }

    if (!value.downstream->closed() && !value.upstream->closed()
        && now - value.last_activity < lifecycle_.idle_timeout) {
        return;
    }
    if (!value.downstream->closed() && !value.upstream->closed()) {
        ++idle_timeouts_;
        log().dia("session %llu idle timeout", static_cast<unsigned long long>(value.id));
    }
    start_draining(value, now);
}

bool listener_service::flush_session_output(session& value) {
    if (!value.client_endpoint.valid() || !value.target_endpoint.valid()) return true;
    if (listener_->flush_output(value.client_endpoint, value.target_endpoint)) return true;

    fail("OpenSSL QUIC connection output failure: " + listener_->last_error());
    return false;
}

void listener_service::reap_expired(std::chrono::steady_clock::time_point now) {
    auto const before = sessions_.size();
    sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(), [&](auto& value) {
        return value.state == session_state::draining
            && now - value.draining_since >= lifecycle_.drain_timeout;
    }), sessions_.end());

    auto const removed = before - sessions_.size();
    connection_count_ -= removed;
    completed_sessions_ += removed;

    // A verified upstream can outlive a client that disappeared before accept.
    // Bound that orphan state by the same handshake timeout.
    for (auto iterator = staged_upstreams_.begin(); iterator != staged_upstreams_.end();) {
        if (now - iterator->second.created < lifecycle_.handshake_timeout) {
            ++iterator;
            continue;
        }
        iterator->second.connection->close();
        ++upstream_failures_;
        iterator = staged_upstreams_.erase(iterator);
    }
}

void listener_service::publish_session_snapshots(
    std::chrono::steady_clock::time_point now) {
    std::vector<session_snapshot> result;
    result.reserve(sessions_.size());
    for (auto const& linked : sessions_) {
        session_snapshot item;
        item.id = linked.id;
        item.state = linked.state == session_state::handshake ? "handshake"
                   : linked.state == session_state::active ? "active" : "draining";
        item.client = endpoint_text(linked.client_endpoint);
        item.target = endpoint_text(linked.target_endpoint);
        if (linked.downstream) {
            item.server_name = linked.downstream->server_name();
            item.downstream_alpn = linked.downstream->negotiated_alpn();
        }
        if (item.target == "-") {
            auto const& host = upstream_host_.empty() ? item.server_name : upstream_host_;
            if (!host.empty()) item.target = host + ":" + std::to_string(upstream_port_);
        }
        if (linked.upstream) item.upstream_alpn = linked.upstream->negotiated_alpn();
        item.age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - linked.created).count();
        item.idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - linked.last_activity).count();
        item.forwarded_bytes = linked.forwarded_bytes;
        if (linked.proxy) {
            item.streams = linked.proxy->pair_count();
            item.queued_bytes = linked.proxy->queued_bytes();
            item.stream_limit_rejections = linked.proxy->limit_rejections();
        }
        result.push_back(std::move(item));
    }
    std::lock_guard<std::mutex> lock(snapshots_mutex_);
    snapshots_.swap(result);
}

void listener_service::start_draining(session& value,
                                      std::chrono::steady_clock::time_point now,
                                      std::uint64_t protocol_error) {
    if (value.state == session_state::draining) return;
    log().dia("session %llu draining protocol-error=%llu forwarded=%llu",
              static_cast<unsigned long long>(value.id),
              static_cast<unsigned long long>(protocol_error),
              static_cast<unsigned long long>(value.forwarded_bytes));
    value.state = session_state::draining;
    value.draining_since = now;
    value.proxy.reset();
    if (value.downstream) value.downstream->close(protocol_error);
    if (value.upstream) value.upstream->close(protocol_error);
}

void listener_service::cleanup_sessions() {
    completed_sessions_ += sessions_.size();
    for (auto& linked : sessions_) {
        if (linked.downstream) linked.downstream->close();
        if (linked.upstream) linked.upstream->close();
    }
    sessions_.clear();
    for (auto& staged : staged_upstreams_) staged.second.connection->close();
    staged_upstreams_.clear();
    for (auto& job : certificate_jobs_) {
        try {
            auto result = job.second.result.get();
            if (result.connection) result.connection->close();
        } catch (...) {
        }
    }
    certificate_jobs_.clear();
    original_destinations_.clear();
    {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);
        snapshots_.clear();
    }
    connection_count_ = 0;
}
#endif

#if SMITHPROXY_OPENSSL_QUIC
int listener_service::certificate_callback(SSL* ssl, void* argument) {
    auto* service = static_cast<listener_service*>(argument);
    return service ? service->prepare_verified_certificate(ssl) : 0;
}

int listener_service::prepare_verified_certificate(SSL* downstream) {
    if (!downstream) return 0;
    if (staged_upstreams_.find(downstream) != staged_upstreams_.end()) return 1;

    if (auto found = certificate_jobs_.find(downstream);
        found != certificate_jobs_.end()) {
        if (found->second.result.wait_for(std::chrono::milliseconds(0))
            != std::future_status::ready) {
            log().deb("certificate job still pending");
            return -1;
        }
        verified_certificate verified;
        try {
            verified = found->second.result.get();
        } catch (...) {
            log().err("certificate job raised an exception");
            certificate_jobs_.erase(found);
            return 0;
        }
        auto const client = found->second.client;
        auto const destination = found->second.destination;
        certificate_jobs_.erase(found);
        if (!verified.connection || !install_verified_certificate(downstream, verified)) {
            ++upstream_failures_;
            log().war("verified certificate preparation failed for peer=%s target=%s",
                      endpoint_text(client).c_str(), endpoint_text(destination).c_str());
            if (verified.connection) verified.connection->close(1);
            return 0;
        }
        staged_upstreams_.emplace(downstream, staged_upstream {
            std::move(verified.connection), client, destination });
        return 1;
    }

    auto const* raw_name = SSL_get_servername(downstream, TLSEXT_NAMETYPE_host_name);
    if (!raw_name || *raw_name == '\0') {
        log().war("downstream handshake rejected: SNI is missing");
        return 0;
    }
    std::string const server_name(raw_name);
    datagram_endpoint peer_endpoint;
    BIO_ADDR* peer_address = BIO_ADDR_new();
    if (peer_address) {
        if (BIO_dgram_get_peer(SSL_get_rbio(downstream), peer_address) > 0) {
            peer_endpoint = endpoint_from_bio_address(peer_address);
        }
        BIO_ADDR_free(peer_address);
    }
    // A listener backed by a datagram pair does not copy its per-packet peer
    // into the accepted connection BIO. The certificate callback is invoked
    // synchronously while the dispatcher is processing the ClientHello, so
    // its current tuple is the authoritative metadata for this SSL object.
    if (!peer_endpoint.valid() && listener_) {
        peer_endpoint = listener_->current_peer();
    }
    datagram_endpoint destination;
    if (transparent_) {
        auto found_destination = original_destinations_.find(endpoint_key(peer_endpoint));
        if (found_destination != original_destinations_.end()) {
            destination = found_destination->second;
            original_destinations_.erase(found_destination);
        } else if (listener_) {
            destination = listener_->current_local();
        }
        if (!destination.valid()) {
            log().war("downstream handshake rejected: original destination missing for %s",
                      endpoint_text(peer_endpoint).c_str());
            return 0;
        }
        std::uint16_t destination_port = 0;
        auto const family = destination.address.ss_family;
        if (family == AF_INET) {
            destination_port = ntohs(reinterpret_cast<sockaddr_in const*>(
                &destination.address)->sin_port);
        } else if (family == AF_INET6) {
            destination_port = ntohs(reinterpret_cast<sockaddr_in6 const*>(
                &destination.address)->sin6_port);
        }
        // A shared UDP socket cannot select a different source port per datagram.
        // Bare transparent mode therefore requires TPROXY --on-port 0 and a
        // listener bound to the original service port.
        if (destination_port == 0 || destination_port != bound_port_) {
            log().war("downstream handshake rejected: destination %s does not match listener port %u",
                      endpoint_text(destination).c_str(), bound_port_);
            return 0;
        }
    }
    if (certificate_jobs_.size() >= limits_.max_certificate_jobs) {
        ++certificate_job_limit_rejections_;
        log().war("certificate job rejected: listener limit %zu reached",
                  limits_.max_certificate_jobs);
        return 0;
    }
    log().deb("starting certificate job sni='%s' peer=%s target=%s",
              server_name.c_str(), endpoint_text(peer_endpoint).c_str(),
              endpoint_text(destination).c_str());
    try {
        certificate_jobs_.emplace(
            downstream,
            certificate_job { std::async(std::launch::async,
                [this, destination, server_name]() mutable {
                    return verify_and_spoof(std::move(destination), std::move(server_name));
                }), peer_endpoint, destination });
    } catch (...) {
        log().err("cannot start certificate job sni='%s'", server_name.c_str());
        return 0;
    }
    return -1;
}

listener_service::verified_certificate listener_service::verify_and_spoof(
    datagram_endpoint destination, std::string server_name) {
    verified_certificate verified;
    auto upstream = transparent_
        ? connect_upstream(destination, server_name)
        : connect_upstream(server_name);
    if (!upstream) {
        log().war("upstream connect failed sni='%s' target=%s", server_name.c_str(),
                  endpoint_text(destination).c_str());
        return verified;
    }

    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!upstream->handshake_complete() && !upstream->closed()
           && std::chrono::steady_clock::now() < deadline) {
        upstream->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!upstream->handshake_complete()
        || SSL_get_verify_result(upstream->native_handle()) != X509_V_OK) {
        log().war("upstream verification failed sni='%s' target=%s verify=%ld",
                  server_name.c_str(), endpoint_text(destination).c_str(),
                  SSL_get_verify_result(upstream->native_handle()));
        upstream->close(1);
        return verified;
    }
    if (upstream->negotiated_alpn() != "h3") {
        log().war("upstream ALPN rejected sni='%s' negotiated='%s'",
                  server_name.c_str(), upstream->negotiated_alpn().c_str());
        upstream->close(1);
        return verified;
    }

    X509* certificate = SSL_get1_peer_certificate(upstream->native_handle());
    if (!certificate) {
        upstream->close(1);
        return verified;
    }
    if (X509_check_host(certificate, server_name.c_str(), server_name.size(), 0, nullptr) != 1) {
        log().war("upstream identity mismatch sni='%s'", server_name.c_str());
        X509_free(certificate);
        upstream->close(1);
        return verified;
    }

    SpoofOptions options;
    options.sni = server_name;
    auto& factory = SSLFactory::factory();
    auto const store_key = SSLFactory::make_store_key(certificate, options);
    auto lock = std::scoped_lock(factory.lock());
    auto retain = [&verified](X509* cert, EVP_PKEY* key) {
        if (!cert || !key || X509_up_ref(cert) != 1) return false;
        if (EVP_PKEY_up_ref(key) != 1) {
            X509_free(cert);
            return false;
        }
        verified.certificate = std::shared_ptr<X509>(cert, X509_free);
        verified.private_key = std::shared_ptr<EVP_PKEY>(key, EVP_PKEY_free);
        return true;
    };
    auto cached = factory.find_mitm(store_key);
    bool ready = cached && retain(cached->chain.cert, cached->chain.key);
    if (!ready) {
        auto forged = factory.spoof(certificate, false, nullptr);
        if (forged && forged->chain.cert && forged->chain.key) {
            ready = retain(forged->chain.cert, forged->chain.key);
            // ptr_cache uses allocator state tied to the allocating thread.
            // Certificate jobs run asynchronously, so publishing a new cache
            // node here would leave teardown to free it from another thread.
            // Keep the retained result session-local; existing cache entries
            // remain readable until cache publication is moved to its owner.
            X509_free(forged->chain.cert);
            forged->nullify(); // SSLFactory::spoof() returns def_sr_key as borrowed.
        }
    }
    X509_free(certificate);
    if (!ready) {
        log().err("certificate spoof failed sni='%s'", server_name.c_str());
        upstream->close(1);
        return {};
    }
    log().deb("certificate ready sni='%s' target=%s", server_name.c_str(),
              endpoint_text(destination).c_str());
    verified.connection = std::move(upstream);
    return verified;
}

bool listener_service::install_verified_certificate(
    SSL* downstream, verified_certificate const& verified) {
    return downstream && verified.certificate && verified.private_key
        && SSL_use_certificate(downstream, verified.certificate.get()) == 1
        && SSL_use_PrivateKey(downstream, verified.private_key.get()) == 1
        && SSL_check_private_key(downstream) == 1;
}

std::shared_ptr<openssl_connection> listener_service::connect_upstream(
    std::string const& host) {
    if (host.empty() || !client_context_) return nullptr;
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo* addresses = nullptr;
    auto const port = std::to_string(upstream_port_);
    auto const& address_host = upstream_host_.empty() ? host : upstream_host_;
    if (::getaddrinfo(address_host.c_str(), port.c_str(), &hints, &addresses) != 0) {
        return nullptr;
    }

    std::shared_ptr<openssl_connection> result;
    for (auto* current = addresses; current && !result; current = current->ai_next) {
        std::string error;
        auto connection = connect_openssl_quic(client_context_.get(), current->ai_addr,
                                                current->ai_addrlen, host, &error);
        if (connection) result = std::shared_ptr<openssl_connection>(std::move(connection));
    }
    ::freeaddrinfo(addresses);
    return result;
}

std::shared_ptr<openssl_connection> listener_service::connect_upstream(
    datagram_endpoint const& target, std::string const& server_name) {
    if (!target.valid() || server_name.empty() || !client_context_) return nullptr;
    std::string error;
    auto connection = connect_openssl_quic(
        client_context_.get(), reinterpret_cast<sockaddr const*>(&target.address),
        target.size, server_name, &error);
    return connection
        ? std::shared_ptr<openssl_connection>(std::move(connection))
        : nullptr;
}
#endif

void listener_service::stop() {
    stopping_ = true;
#if SMITHPROXY_OPENSSL_QUIC
    if (wake_fd_ >= 0) {
        // Nonblocking eventfd may only fail here if it is already saturated;
        // in that case it is already readable and poll() will still wake.
        ::eventfd_write(wake_fd_, 1);
    }
#endif
}

} // namespace sx::quic
