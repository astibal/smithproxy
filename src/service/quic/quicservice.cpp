#include "proxy/quic/error_stats.hpp"
#include <privileged_socket.hpp>
#include <vars.hpp>
#include "service/quic/quicservice.hpp"

#include "proxy/quic/spq1.hpp"
#include "service/quic/quiclog.hpp"
#include "service/quic/worker_dispatcher.hpp"
#include <stdexcept>

#include <traflog/pcapapi.hpp>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
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
#include "service/quic/certificate_verifier.hpp"
#endif

namespace sx::quic {

namespace {

#if SMITHPROXY_OPENSSL_QUIC
int select_h3(SSL*, const unsigned char** output, unsigned char* output_size,
              const unsigned char* input, unsigned input_size, void*) {
    static constexpr unsigned char supported[] = { 2, 'h', '3' };
    bool const accepted = SSL_select_next_proto(const_cast<unsigned char**>(output), output_size,
                                                supported, sizeof(supported), input, input_size)
        == OPENSSL_NPN_NEGOTIATED;
    try {
        if (accepted) {
            logging::alpn().deb("A selected h3 from %u bytes of ALPN offers", input_size);
        } else {
            logging::alpn().war("A rejected ClientHello: h3 not offered");
        }
    } catch (...) {
        ++stats.errors.logging_alpn_exception;
    }
    return accepted ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
}

bool use_pem_credentials(SSL_CTX* context, const std::string& certificate,
                         const std::string& private_key) {
    auto cert_bio = std::unique_ptr<BIO, decltype(&BIO_free)>(
        BIO_new_mem_buf(certificate.data(), static_cast<int>(certificate.size())), BIO_free);
    auto key_bio = std::unique_ptr<BIO, decltype(&BIO_free)>(
        BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size())), BIO_free);
    if (!cert_bio || !key_bio) return false;

    auto cert = std::unique_ptr<X509, decltype(&X509_free)>(
        PEM_read_bio_X509_AUX(cert_bio.get(), nullptr, nullptr, nullptr), X509_free);
    auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(
        PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    return cert && key && SSL_CTX_use_certificate(context, cert.get()) == 1
        && SSL_CTX_use_PrivateKey(context, key.get()) == 1
        && SSL_CTX_check_private_key(context) == 1;
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

buffer make_udp_packet(datagram_view const& datagram) {
    if (!datagram.peer.valid() || !datagram.local.valid()
        || !datagram.data || datagram.size == 0) return buffer();

    auto const& source = datagram.direction == datagram_direction::ingress
        ? datagram.peer : datagram.local;
    auto const& destination = datagram.direction == datagram_direction::ingress
        ? datagram.local : datagram.peer;
    if (source.address.ss_family != destination.address.ss_family) return buffer();

    socle::pcap::connection_details details {};
    details.next_proto = socle::pcap::connection_details::UDP;
    details.source = source.address;
    details.destination = destination.address;

    buffer packet;
    auto const* payload = reinterpret_cast<char const*>(datagram.data);
    socle::pcap::append_IP_header(packet, details, 0, datagram.size);
    socle::pcap::append_UDP_header(packet, details, 0, payload, datagram.size);
    packet.append(payload, datagram.size);
    return packet;
}

#endif

} // namespace

listener_service::listener_service(std::uint16_t port, std::string certificate,
                                   std::string private_key, bool transparent,
                                   std::uint16_t upstream_port, bool verify_upstream,
                                   lifecycle_options lifecycle, resource_limits limits,
                                   std::string upstream_host,
                                   flow_proxy_factory proxy_factory,
                                   bool capture_native,
                                   proxymaker::SessionSetupFactory setup_factory,
                                   std::optional<std::string> certificate_pem,
                                   std::optional<std::string> private_key_pem, int address_family,
                                   int receive_buffer)
    : receive_buffer_requested_(receive_buffer), address_family_(address_family),
      port_(port), certificate_(std::move(certificate)),
      private_key_(std::move(private_key)),
      certificate_pem_(std::move(certificate_pem)),
      private_key_pem_(std::move(private_key_pem)), transparent_(transparent),
      upstream_port_(upstream_port), upstream_host_(std::move(upstream_host)),
      verify_upstream_(verify_upstream), lifecycle_(lifecycle), limits_(limits),
      setup_factory_(std::move(setup_factory)),
      proxy_factory_(std::move(proxy_factory)), capture_native_(capture_native) {
    logging::initialize();
}

void listener_service::assign_worker(std::shared_ptr<worker_dispatcher> dispatcher,
                                    std::size_t index) {
#if SMITHPROXY_OPENSSL_QUIC
    if (ready_ || !dispatcher || index >= dispatcher->size()) {
        ++stats.errors.listener_assign_worker_invalid_quic_worker_assignment;
        throw std::logic_error("invalid QUIC worker assignment");
    }
    dispatcher_ = std::move(dispatcher);
    worker_index_ = index;
#endif
}

std::size_t listener_service::worker_count() const {
#if SMITHPROXY_OPENSSL_QUIC
    if (dispatcher_) return dispatcher_->size();
#endif
    return 1;
}

std::uint64_t listener_service::dropped_datagrams() const {
#if SMITHPROXY_OPENSSL_QUIC
    if (dispatcher_) return dispatcher_->dropped(worker_index_);
#endif
    return 0;
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

std::future<listener_service::session_details> listener_service::request_session_details(
    multiflow::flow_proxy::detail_renderer renderer) {
    detail_request request {std::move(renderer), {}};
    auto result = request.result.get_future();
    {
        auto lock = std::scoped_lock(detail_requests_lock_);
        if (!ready_ || stopping_) {
            request.result.set_value({});
            return result;
        }
        detail_requests_.push_back(std::move(request));
    }
#if SMITHPROXY_OPENSSL_QUIC
    if (wake_fd_ >= 0) (void)::eventfd_write(wake_fd_, 1);
#else
    process_detail_requests();
#endif
    return result;
}

void listener_service::process_detail_requests() {
    std::vector<detail_request> requests;
    {
        auto lock = std::scoped_lock(detail_requests_lock_);
        requests.swap(detail_requests_);
    }
    for (auto& request : requests) {
        try {
            session_details result;
#if SMITHPROXY_OPENSSL_QUIC
            for (const auto& session : sessions_) {
                if (session.proxy) result.emplace(
                    session.id, session.proxy->render_details(request.renderer));
            }
#endif
            request.result.set_value(std::move(result));
        } catch (...) {
            ++stats.errors.listener_process_detail_requests_exception;
            request.result.set_exception(std::current_exception());
        }
    }
}

listener_service::~listener_service() {
    stop();
#if SMITHPROXY_OPENSSL_QUIC
    sessions_.clear();
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
    auto close_open_descriptors = [this]() {
        if (udp_fd_ >= 0) {
            ::close(udp_fd_);
            udp_fd_ = -1;
        }
        if (wake_fd_ >= 0) {
            ::close(wake_fd_);
            wake_fd_ = -1;
        }
    };
    close_open_descriptors();
    receive_buffer_actual_ = 0;
    auto fail_open = [this, &close_open_descriptors](std::string message) {
        close_open_descriptors();
        ++stats.errors.listener_open_socket_failure;
        fail(std::move(message));
        return false;
    };
    wake_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd_ < 0) {
        ++stats.errors.listener_open_socket_eventfd;
        return fail_open(std::string("eventfd: ") + std::strerror(errno));
    }
    if (dispatcher_ && dispatcher_->socket_fd() >= 0) {
        udp_fd_ = ::fcntl(dispatcher_->socket_fd(), F_DUPFD_CLOEXEC, 0);
        if (udp_fd_ < 0) {
            ++stats.errors.listener_open_socket_cannot_duplicate_quic_receiver_socket;
            return fail_open("cannot duplicate QUIC receiver socket");
        }
        socklen_t buffer_size = sizeof(receive_buffer_actual_);
        if (::getsockopt(udp_fd_, SOL_SOCKET, SO_RCVBUF,
                         &receive_buffer_actual_, &buffer_size) != 0) {
            ++stats.errors.listener_shared_socket_receive_buffer_readback;
            return fail_open(std::string("SO_RCVBUF readback: ") + std::strerror(errno));
        }
        sockaddr_storage bound {};
        socklen_t size = sizeof(bound);
        if (::getsockname(udp_fd_, reinterpret_cast<sockaddr*>(&bound), &size) != 0) {
            ++stats.errors.listener_open_socket_cannot_inspect_quic_receiver_socket;
            return fail_open("cannot inspect QUIC receiver socket");
        }
        bound_port_ = bound.ss_family == AF_INET
            ? ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port)
            : ntohs(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
        return true;
    }
    if (address_family_ != AF_INET && address_family_ != AF_INET6) {
        ++stats.errors.listener_open_socket_unsupported_quic_listener_address_family;
        return fail_open("unsupported QUIC listener address family");
    }
    udp_fd_ = socle::socket(address_family_, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if (udp_fd_ < 0) {
        ++stats.errors.listener_open_socket_socket;
        return fail_open(std::string("socket: ") + std::strerror(errno));
    }

    // Set only the original A socket, before traffic arrives. Worker duplicates
    // share its receive queue; B sockets keep their independent OS defaults.
    if (receive_buffer_requested_ < 0) {
        ++stats.errors.listener_open_socket_negative_quic_listener_receive_buffer;
        return fail_open("negative QUIC listener receive buffer");
    }
    if (receive_buffer_requested_ > 0
        && socle::setsockopt(udp_fd_, SOL_SOCKET, SO_RCVBUF,
                        &receive_buffer_requested_, sizeof(receive_buffer_requested_)) != 0) {
        ++stats.errors.listener_open_socket_so_rcvbuf;
        return fail_open(std::string("SO_RCVBUF: ") + std::strerror(errno));
    }
    // Read back rather than assume: kernels may clamp the request, and Linux
    // reports twice the requested size to include its bookkeeping allowance.
    socklen_t buffer_size = sizeof(receive_buffer_actual_);
    if (::getsockopt(udp_fd_, SOL_SOCKET, SO_RCVBUF,
                     &receive_buffer_actual_, &buffer_size) != 0) {
        ++stats.errors.listener_open_socket_receive_buffer_readback;
        return fail_open(std::string("SO_RCVBUF readback: ") + std::strerror(errno));
    }

    int enabled = 1;
    if (socle::setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        ++stats.errors.listener_open_socket_so_reuseaddr;
        return fail_open(std::string("SO_REUSEADDR: ") + std::strerror(errno));
    }
    if (address_family_ == AF_INET6
        && socle::setsockopt(udp_fd_, SOL_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) != 0) {
        ++stats.errors.listener_open_socket_ipv6_v6only;
        return fail_open(std::string("IPV6_V6ONLY: ") + std::strerror(errno));
    }
    int const level = address_family_ == AF_INET ? SOL_IP : SOL_IPV6;
    int const transparent_option = address_family_ == AF_INET ? IP_TRANSPARENT : IPV6_TRANSPARENT;
    int const destination_option = address_family_ == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;
    if (transparent_
        && socle::setsockopt(udp_fd_, level, transparent_option, &enabled, sizeof(enabled)) != 0) {
        ++stats.errors.listener_open_socket_ip_transparent;
        return fail_open(std::string("IP_TRANSPARENT: ") + std::strerror(errno));
    }
    if (transparent_
        && socle::setsockopt(udp_fd_, level, destination_option,
                        &enabled, sizeof(enabled)) != 0) {
        ++stats.errors.listener_open_socket_ip_recvorigdstaddr;
        return fail_open(std::string("IP_RECVORIGDSTADDR: ") + std::strerror(errno));
    }

    auto const flags = ::fcntl(udp_fd_, F_GETFL, 0);
    if (flags < 0 || ::fcntl(udp_fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
        ++stats.errors.listener_open_socket_o_nonblock;
        return fail_open(std::string("O_NONBLOCK: ") + std::strerror(errno));
    }

    sockaddr_storage address {};
    socklen_t address_size = 0;
    if (address_family_ == AF_INET) {
        auto* ipv4 = reinterpret_cast<sockaddr_in*>(&address);
        ipv4->sin_family = AF_INET;
        ipv4->sin_addr.s_addr = htonl(INADDR_ANY);
        ipv4->sin_port = htons(port_);
        address_size = sizeof(*ipv4);
    } else {
        auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&address);
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_addr = in6addr_any;
        ipv6->sin6_port = htons(port_);
        address_size = sizeof(*ipv6);
    }
    if (socle::bind(udp_fd_, reinterpret_cast<sockaddr*>(&address), address_size) != 0) {
        ++stats.errors.listener_open_socket_bind;
        return fail_open(std::string("bind: ") + std::strerror(errno));
    }
    if (::getsockname(udp_fd_, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        ++stats.errors.listener_open_socket_getsockname;
        return fail_open(std::string("getsockname: ") + std::strerror(errno));
    }
    bound_port_ = address_family_ == AF_INET
        ? ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port)
        : ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port);
    log().dia("socket ready on udp/*:%u transparent=%d rcvbuf requested=%d actual=%d",
              bound_port_, transparent_, receive_buffer_requested_, receive_buffer_actual_);
    return true;
#else
    ++stats.errors.listener_open_socket_openssl_was_built_without_quic_server_support_requires_openssl_3_5;
    fail("OpenSSL was built without QUIC server support (requires OpenSSL 3.5+)");
    return false;
#endif
}

bool listener_service::prepare() {
#if SMITHPROXY_OPENSSL_QUIC
    if (ready_) return true;
    listener_.reset();
    backend_ = configured_transport_backend();
    // A previous prepare may have opened the transport successfully and then
    // failed while constructing the worker transport. Do not retain or
    // overwrite those descriptors on a retry.
    if (udp_fd_ >= 0) {
        ::close(udp_fd_);
        udp_fd_ = -1;
    }
    if (wake_fd_ >= 0) {
        ::close(wake_fd_);
        wake_fd_ = -1;
    }
    stopping_ = false;
    context_ = make_transport_context(backend_, true);
    client_context_ = make_transport_context(backend_, false);
    if (!context_ || !client_context_) {
        ++stats.errors.listener_prepare_cannot_create_quic_context_check_backend_availability;
        fail("cannot create QUIC context (check backend availability): " + openssl_error_stack());
        return false;
    }
    const bool native_credentials = certificate_pem_.has_value() || private_key_pem_.has_value();
    const bool credentials_loaded = native_credentials
        ? certificate_pem_ && private_key_pem_
            && use_pem_credentials(context_.get(), *certificate_pem_, *private_key_pem_)
        : SSL_CTX_use_certificate_chain_file(context_.get(), certificate_.c_str()) == 1
            && SSL_CTX_use_PrivateKey_file(context_.get(), private_key_.c_str(), SSL_FILETYPE_PEM) == 1
            && SSL_CTX_check_private_key(context_.get()) == 1;
    if (!credentials_loaded) {
        ++stats.errors.listener_prepare_cannot_load_quic_certificate_key;
        fail("cannot load QUIC certificate/key: " + openssl_error_stack());
        return false;
    }
    SSL_CTX_set_alpn_select_cb(context_.get(), select_h3, nullptr);
    SSL_CTX_set_client_hello_cb(context_.get(), client_hello_callback, this);
    if (verify_upstream_) {
        SSL_CTX_set_verify(client_context_.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_cert_cb(context_.get(), certificate_callback, this);
    } else {
        SSL_CTX_set_verify(client_context_.get(), SSL_VERIFY_NONE, nullptr);
    }
    if (!open_socket()) return false;
    // Both sides of every A:B pair stay on this worker. Each backend owns
    // one incoming and one outgoing transport scheduler, with shared sockets.
    datagram_source source;
    if (dispatcher_) {
        if (!dispatcher_->attach_socket(udp_fd_)) {
            ++stats.errors.listener_prepare_cannot_retain_quic_receiver_socket;
            fail("cannot retain QUIC receiver socket");
            return false;
        }
        source = [this](datagram_packet* packets, size_t capacity) {
            return dispatcher_->pop_batch(worker_index_, packets, capacity);
        };
    }
    listener_ = make_worker_transport(
        backend_, context_.get(), client_context_.get(), udp_fd_, address_family_,
        transparent_ || bool(dispatcher_),
        [this](datagram_view const& datagram) { observe_datagram(datagram); },
        std::move(source), limits_.max_sessions);
    if (!listener_) {
        ++stats.errors.listener_prepare_cannot_create_quic_worker_transport;
        fail("cannot create QUIC worker transport: " + openssl_error_stack());
        return false;
    }
    ready_ = true;
    last_error_.clear();
    log().inf("listener ready on udp/*:%u verify-upstream=%d backend=%s", bound_port_, verify_upstream_,
              backend_ == transport_backend::ngtcp2 ? "ngtcp2" : "openssl");
    return true;
#else
    return open_socket();
#endif
}

void listener_service::run() {
#if SMITHPROXY_OPENSSL_QUIC
    if (!ready_ && !prepare()) return;
    log().inf("listener loop started on udp/*:%u worker=%zu/%zu", bound_port_,
              worker_index_, worker_count());
    if (dispatcher_ && !dispatcher_->start()) {
        ++stats.errors.listener_run_cannot_start_quic_receiver;
        fail("cannot start QUIC receiver");
        dispatcher_->retire(worker_index_);
        return;
    }

    bool application_progress = false;
    while (!stopping_) {
        if (dispatcher_ && dispatcher_->error() != 0) {
            ++stats.errors.listener_run_quic_receiver;
            fail(std::string("QUIC receiver: ") + std::strerror(dispatcher_->error()));
            break;
        }
        // Every engine pass is followed by application work. A productive
        // application pass queues transport work for the next round, so only
        // an unproductive pass may wait for network input or a deadline.
        if (!application_progress && !wait_for_work()) break;

        // Do not pre-classify this shared UDP socket with MSG_PEEK. OpenSSL may
        // receive a batch after the peek, so a following DTLS datagram could
        // still cross that boundary and make the apparent demultiplexing racy.
        // Supporting QUIC and DTLS on one port requires a dispatcher which owns
        // recvmsg() and injects only classified QUIC datagrams into OpenSSL.
        if (!listener_->handle_events() && !stopping_) {
            auto detail = listener_->last_error();
            if (detail.empty()) detail = openssl_error_stack();
            ++stats.errors.listener_run_quic_listener_event_failure;
            fail("QUIC listener event failure: " + detail);
            break;
        }
        // One receive/timer pass for all B connections, including certificate
        // jobs and connections waiting to be attached to an accepted A.
        if (!progress_upstream_engine()) break;

        // During live reconfiguration, keep servicing established sessions but
        // stop admitting new ones until the listener can leave naturally.
        application_progress = progress_certificate_jobs();
        if (!draining_) application_progress = accept_connections() || application_progress;
        auto const now = std::chrono::steady_clock::now();
        // Revisit productive sessions without sleeping, but give every A:B
        // pair its turn. Reads, FIN/reset and lifecycle changes count too.
        for (auto& linked : sessions_) {
            auto const before = linked.forwarded_bytes;
            auto const previous_state = linked.state;
            progress_session(linked, now);
            application_progress = application_progress || linked.forwarded_bytes != before
                || linked.state != previous_state;
            if (linked.downstream)
                application_progress = linked.downstream->take_application_progress() || application_progress;
            if (linked.upstream)
                application_progress = linked.upstream->take_application_progress() || application_progress;
            if (!flush_session_output(linked)) {
                stopping_ = true;
                break;
            }
            // Flushing may generate the final handshake/shutdown secrets.
            publish_capture_secrets(linked);
        }

        // Do not tick either engine here: a purported output-only tick can
        // receive more input. The next round flushes queued writes and then
        // visits their application consumers before considering a sleep.

        // Publish only after removing objects whose grace period has elapsed.
        application_progress = reap_expired(now) || application_progress;
        publish_session_snapshots(now);
        process_detail_requests();
        if (draining_ && sessions_.empty() && certificate_jobs_.empty() &&
            staged_upstreams_.empty() && pending_captures_.empty() &&
            dispatcher_bindings_.empty()) stopping_ = true;
    }
    cleanup_sessions();
    if (dispatcher_) dispatcher_->retire(worker_index_);
    process_detail_requests();
    log().inf("listener loop stopped on udp/*:%u", bound_port_);
#endif
}

#if SMITHPROXY_OPENSSL_QUIC
bool listener_service::wait_for_work() {
    // With no retained work, wait solely for network input or stop().
    // Retained sessions need bounded lifecycle/verification checks as well as
    // wakeups for the earlier of the two engines' transport deadlines.
    auto const application_timeout = sessions_.empty() && certificate_jobs_.empty()
            && staged_upstreams_.empty() && pending_captures_.empty()
            && dispatcher_bindings_.empty()
        ? -1
        : 50;
    auto timeout = listener_->timeout();
    if (application_timeout >= 0) {
        auto cap = std::chrono::milliseconds(application_timeout);
        if (timeout.count() < 0 || cap < timeout) timeout = cap;
    }
    timespec deadline {};
    if (timeout.count() >= 0) {
        deadline.tv_sec = timeout.count() / 1000000000;
        deadline.tv_nsec = timeout.count() % 1000000000;
    }

    // Both engines expose one socket each. Pending certificate jobs and
    // accepted sessions share the same upstream readiness and deadline.
    std::vector<pollfd> descriptors {
        { udp_fd_, static_cast<short>(listener_->desired_socket_events()
            & (dispatcher_ ? ~POLLIN : ~0)), 0 },
        { wake_fd_, POLLIN, 0 },
        { listener_->upstream_fd(), listener_->upstream_events(), 0 },
    };
    if (dispatcher_) descriptors.push_back(
        {dispatcher_->wake_fd(worker_index_), POLLIN, 0});

    log().dum("poll listener-events=0x%x fds=%zu timeout-ns=%lld sessions=%zu cert-jobs=%zu",
              descriptors[0].events, descriptors.size(), static_cast<long long>(timeout.count()),
              sessions_.size(), certificate_jobs_.size());
    auto const polled = ::ppoll(descriptors.data(), descriptors.size(), timeout.count() < 0 ? nullptr : &deadline, nullptr);
    if (polled < 0 && errno != EINTR) {
        ++stats.errors.listener_wait_for_work_poll;
        fail(std::string("poll: ") + std::strerror(errno));
        return false;
    }
    if (descriptors[1].revents & POLLIN) {
        eventfd_t wakeups = 0;
        while (::eventfd_read(wake_fd_, &wakeups) == 0) {
        }
    }
    if (descriptors[0].revents != 0) {
        log().dum("network wake revents=0x%x", descriptors[0].revents);
    }
    return !stopping_;
}

void listener_service::observe_datagram(datagram_view const& datagram) {
    // Log arguments are evaluated even when ext() discards the message. Do
    // not format two socket addresses per packet with packet logging disabled.
    if (datagram.direction == datagram_direction::ingress && *log().level() >= EXT) {
        log().ext("datagram peer=%s original-destination=%s association=%llu",
                  endpoint_text(datagram.peer).c_str(), endpoint_text(datagram.local).c_str(),
                  static_cast<unsigned long long>(datagram.association));
    }
    if (!capture_native_ || datagram.association == 0) return;

    std::shared_ptr<sx::session_traffic_log> capture;
    if (auto route = capture_routes_.find(datagram.association);
        route != capture_routes_.end()) {
        capture = route->second.lock();
        if (!capture) capture_routes_.erase(route);
    }
    if (!capture) {
        auto pending = pending_captures_.find(datagram.association);
        if (pending == pending_captures_.end()) {
            if (pending_captures_.size() >= limits_.max_pending_capture_sessions) return;
            pending = pending_captures_.emplace(
                datagram.association,
                pending_capture {
                    std::make_shared<sx::session_traffic_log>(
                        limits_.native_capture_buffer_bytes),
                    std::chrono::steady_clock::now(),
                }).first;
        }
        pending->second.updated = std::chrono::steady_clock::now();
        capture = pending->second.log;
        capture_routes_[datagram.association] = capture;
    }

    auto packet = make_udp_packet(datagram);
    if (!packet.empty()) {
        capture->write_packet(datagram.direction == datagram_direction::ingress
                                  ? socle::side_t::LEFT : socle::side_t::RIGHT,
                              packet);
    }
}

void listener_service::publish_capture_secrets(session& value) {
    if (!value.capture_log || !value.keylog || !value.downstream
        || !value.downstream->handshake_complete()) return;
    auto lines = value.keylog->snapshot(value.keylog_cursor);
    if (lines.empty()) return;

    // Wireshark treats a TLS-keylog DSB as a self-contained key schedule. The
    // accepted handshake already has both directions' handshake and 1-RTT
    // secrets, so publish one complete multi-line block rather than one DSB
    // per callback line.
    std::string keylog;
    for (auto const& line : lines) {
        keylog.append(line);
        keylog.push_back('\n');
    }
    buffer data(keylog.data(), keylog.size());
    value.capture_log->write_secret(socle::traffic_secret_format::tls_key_log, data);
    value.keylog_cursor = lines.size();
}

void listener_service::attach_staged_upstream(session& value) {
    if (!value.downstream || value.upstream) return;

    // The certificate callback knows the transparent tuple before OpenSSL
    // publishes the accepted connection object. Preserve it across that gap.
    auto* key = value.downstream->handle_native();
    if (auto pending = certificate_jobs_.find(key); pending != certificate_jobs_.end()) {
        value.created = std::min(value.created, pending->second.created);
        value.client_endpoint = pending->second.client;
        value.target_endpoint = pending->second.destination;
    }

    auto found = staged_upstreams_.find(key);
    if (found == staged_upstreams_.end()) return;

    if (!value.client_endpoint.valid()) value.client_endpoint = found->second.client;
    value.target_endpoint = found->second.destination;
    value.setup = found->second.setup;
    // OpenSSL may publish the accepted connection before a suspended
    // certificate callback has collected its prepared certificate. Keep the
    // generation binding until that result has been installed and staged;
    // otherwise the resumed callback observes generation zero and rejects the
    // very handshake which owns this session.
    dispatcher_bindings_.erase(key);
    value.upstream = std::move(found->second.connection);
    staged_upstreams_.erase(found);
    if (!value.upstream) {
        ++upstream_failures_;
        value.downstream->close(1);
        return;
    }
    if (!value.target_endpoint.valid()) value.target_endpoint = value.upstream->peer_endpoint();
}

bool listener_service::prepare_resumed_upstream(session& value) {

    auto const server_name = value.downstream->server_name();
    auto const [target_host, target_port] = endpoint_parts(value.target_endpoint);
    if(server_name.empty() || !value.client_endpoint.valid()
       || (transparent_ && (target_host.empty() || target_port != std::to_string(bound_port_)))) {
        ++upstream_failures_;
        log().war("resumed session %llu has no valid SNI or original tuple",
                  static_cast<unsigned long long>(value.id));
        return false;
    }

    // The ticket authenticates the downstream handshake only. The new upstream
    // still uses peer/hostname verification and the usual policy and hook path.
    if(!value.setup && setup_factory_) {
        auto const [host, port] = endpoint_parts(value.client_endpoint);
        value.setup = setup_factory_(host, port);
    }

    value.upstream = transparent_
        ? connect_upstream(value.target_endpoint, server_name, value.setup.get())
        : connect_upstream(server_name, value.setup.get());
    dispatcher_bindings_.erase(value.downstream->handle_native());

    if(!value.upstream) {
        ++upstream_failures_;
        log().war("resumed session %llu cannot create upstream connection",
                  static_cast<unsigned long long>(value.id));
        return false;
    }

    if(!value.target_endpoint.valid()) value.target_endpoint = value.upstream->peer_endpoint();
    return true;
}

bool listener_service::accept_connections() {
    bool accepted_any = false;
    while (auto accepted = listener_->accept()) {
        accepted_any = true;
        auto connection = std::shared_ptr<transport_connection>(std::move(accepted));

        // Refuse excess work before allocating session/proxy state.
        if (sessions_.size() >= limits_.max_sessions) {
            ++session_limit_rejections_;
            log().war("session rejected: listener limit %zu reached", limits_.max_sessions);
            if (auto binding = dispatcher_bindings_.find(connection->handle_native());
                binding != dispatcher_bindings_.end()) {
                pending_captures_.erase(binding->second.association);
                capture_routes_.erase(binding->second.association);
                dispatcher_bindings_.erase(binding);
            }
            connection->close(0x107);
            continue;
        }

        session incoming;
        incoming.id = next_session_id_++;
        incoming.downstream = std::move(connection);
        incoming.keylog = incoming.downstream->keylog();
        incoming.client_endpoint = incoming.downstream->peer_endpoint();
        auto* ssl = incoming.downstream->handle_native();
        if (auto binding = dispatcher_bindings_.find(ssl);
            binding != dispatcher_bindings_.end()) {
            if(binding->second.client.valid()) incoming.client_endpoint = binding->second.client;
            incoming.target_endpoint = binding->second.destination;
            incoming.capture_association = binding->second.association;
            incoming.setup = binding->second.setup;
            incoming.ingress_ifindex = binding->second.ingress_ifindex;
            if (capture_native_) {
                if (auto pending = pending_captures_.find(incoming.capture_association);
                    pending != pending_captures_.end()) {
                    incoming.capture_log = std::move(pending->second.log);
                    pending_captures_.erase(pending);
                }
                if (!incoming.capture_log) {
                    incoming.capture_log = std::make_shared<sx::session_traffic_log>(
                        limits_.native_capture_buffer_bytes);
                }
                capture_routes_[incoming.capture_association] = incoming.capture_log;
            }
        }
        attach_staged_upstream(incoming);

        sessions_.push_back(std::move(incoming));
        snapshots_dirty_ = true;
        ++connection_count_;
        ++accepted_sessions_;

        auto const& value = sessions_.back();
        logging::session().inf("session %llu accepted from %s",
                               static_cast<unsigned long long>(value.id),
                               endpoint_text(value.client_endpoint).c_str());
    }
    return accepted_any;
}

void listener_service::progress_session(
    session& value, std::chrono::steady_clock::time_point now) {
    switch (value.state) {
    case session_state::handshake:
        // Keep certificate/TLS phases observable even between state changes.
        snapshots_dirty_ = true;
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

    if (now - value.created >= lifecycle_.handshake_timeout) {
        ++handshake_timeouts_;
        logging::session().war("session %llu handshake timed out",
                               static_cast<unsigned long long>(value.id));
        start_draining(value, now, 0, "handshake timeout");
        return;
    }

    // Keep progressing ACKs, final handshake flight, and timers under this
    // session's tuple. progress_transport() deliberately does not dequeue
    // flow_open, so early application streams remain available to the bridge.
    value.downstream->progress_transport();

    // A resumed handshake does not enter OpenSSL's certificate callback.
    // Prepare its normal verified forwarding leg before publishing outcomes.
    if(verify_upstream_ && !value.upstream && value.downstream->handshake_complete()
       && SSL_session_reused(value.downstream->handle_native())) {
        if(!prepare_resumed_upstream(value)) {
            start_draining(value, now, 0, "upstream connect failed");
            return;
        }
    }

    if(!hook_outcome(value.setup.get(), value.downstream->handle_native(), true)) {
        start_draining(value, now, 0, "downstream hook rejected");
        return;
    }

    if (value.downstream->closed()) {
        ++handshake_failures_;
        logging::info().war("session %llu downstream handshake failed",
                            static_cast<unsigned long long>(value.id));
        start_draining(value, now, 0, "downstream handshake failed");
        return;
    }

    // Tests may skip origin verification; production receives its upstream
    // connection from the certificate job above.
    if (!verify_upstream_ && value.downstream->handshake_complete() && !value.upstream) {
        if (!value.setup && setup_factory_) {
            auto const [host, port] = endpoint_parts(value.client_endpoint);
            value.setup = setup_factory_(host, port);
        }
        value.upstream = connect_upstream(value.downstream->server_name(), value.setup.get());
        if (!value.upstream) {
            ++upstream_failures_;
            log().war("session %llu cannot create upstream connection",
                      static_cast<unsigned long long>(value.id));
            start_draining(value, now, 0, "upstream connect failed");
        }
        return;
    }
    if (!value.upstream) return;

    value.upstream->progress_transport();
    if(!hook_outcome(value.setup.get(), value.upstream->handle_native(), false)) {
        start_draining(value, now, 0, "upstream hook rejected");
        return;
    }
    if (value.upstream->closed()) {
        ++upstream_failures_;
        logging::info().war("session %llu upstream handshake failed",
                            static_cast<unsigned long long>(value.id));
        start_draining(value, now, 0, "upstream handshake failed");
        return;
    }
    // ALPN can be selected before TLS completes. Keep the handshake deadline
    // and defer bridge creation until both transports have finished TLS.
    if (!value.upstream->handshake_complete()
        || !value.downstream->handshake_complete()) return;

    // The same upstream supplies the certificate and carries application data.
    // Keep this guard for resumed downstreams, which skip certificate callbacks.
    auto* verifier = certificate_verifier::get(value.upstream->handle_native());
    int const verdict = verifier ? verifier->progress(value.upstream->handle_native())
        : (SSL_get_verify_result(value.upstream->handle_native()) == X509_V_OK ? 1 : -1);
    if (verify_upstream_ && verdict == 0) return;
    if (verify_upstream_ && verdict < 0) {
        ++upstream_failures_;
        log().war("session %llu forwarding upstream verification failed",
                  static_cast<unsigned long long>(value.id));
        start_draining(value, now, 1, "upstream verification failed");
        return;
    }

    // Both legs must agree on the application protocol before streams can be
    // paired. This prevents forwarding bytes between incompatible protocols.
    auto const downstream_alpn = value.downstream->negotiated_alpn();
    auto const upstream_alpn = value.upstream->negotiated_alpn();
    if (downstream_alpn.empty() || downstream_alpn != upstream_alpn) {
        ++alpn_failures_;
        logging::alpn().war("session %llu ALPN mismatch downstream='%s' upstream='%s'",
                            static_cast<unsigned long long>(value.id),
                            downstream_alpn.c_str(), upstream_alpn.c_str());
        start_draining(value, now, 1, "ALPN mismatch");
        return;
    }

    logging::alpn().dia("session %llu A/B negotiated '%s'",
                        static_cast<unsigned long long>(value.id), downstream_alpn.c_str());

    auto const proxy_limits = multiflow::proxy_limits {
        limits_.max_streams_per_session,
        limits_.stream_buffer_bytes,
    };
    if (proxy_factory_) {
        auto [source_host, source_port] = endpoint_parts(value.client_endpoint);
        auto [target_host, target_port] = endpoint_parts(value.target_endpoint);
        auto capture = std::make_shared<spq1::connection_context>(
            value.id, downstream_alpn, value.capture_log);
        multiflow::flow_proxy_context flow_context {
            std::move(source_host), std::move(source_port),
            std::move(target_host), std::move(target_port),
            value.target_endpoint.address.ss_family,
            [capture = std::move(capture)](multiflow::flow_id flow) {
                return std::make_unique<spq1::stream_log_adapter>(
                    spq1::stream_context {capture, flow});
            },
        };
        flow_context.ingress_ifindex = value.ingress_ifindex;
        flow_context.transport_name = "quic";
        if (value.setup) flow_context.parent_connection_id = value.setup->connection_id();

        value.proxy = proxy_factory_(
            value.downstream, value.upstream, proxy_limits,
            std::move(flow_context));
    } else {
        value.proxy = std::make_unique<multiflow::MFProxy>(
            value.downstream, value.upstream, proxy_limits);
    }
    if (!value.proxy) {
        ++upstream_failures_;
        start_draining(value, now, 0, "bridge creation failed");
        return;
    }

    value.state = session_state::active;
    value.last_activity = now;
    logging::session().inf("session %llu active sni='%s' alpn='%s' target=%s",
                           static_cast<unsigned long long>(value.id),
                           value.downstream->server_name().c_str(),
                           downstream_alpn.c_str(), endpoint_text(value.target_endpoint).c_str());
}

void listener_service::progress_active(
    session& value, std::chrono::steady_clock::time_point now) {
    // One pass per session keeps a busy stream from repeatedly driving its
    // engine while siblings wait. The worker revisits productive sessions in
    // the next round without blocking in poll(); that round's transport phase
    // flushes the output queued by all sessions in this pass.
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
    start_draining(value, now, 0,
        value.downstream->closed() || value.upstream->closed() ? "transport closed" : "idle timeout");
}

bool listener_service::flush_session_output(session& value) {
    if (!value.client_endpoint.valid() || !value.target_endpoint.valid()) return true;
    if (listener_->flush_output(value.client_endpoint, value.target_endpoint,
                                value.capture_association)) return true;

    ++stats.errors.listener_flush_session_output_quic_connection_output_failure;
    fail("QUIC connection output failure: " + listener_->last_error());
    return false;
}

bool listener_service::progress_upstream_engine() {
    ERR_clear_error();
    if (listener_->handle_upstream()) return true;
    auto detail = listener_->last_error();
    if (detail.empty()) detail = openssl_error_stack();
    ++stats.errors.listener_progress_upstream_engine_quic_upstream_transport_failure;
    fail("QUIC upstream transport failure: " + detail);
    return false;
}

bool listener_service::reap_expired(std::chrono::steady_clock::time_point now) {
    auto const before = sessions_.size();
    sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(), [&](auto& value) {
        auto const expired = value.state == session_state::draining
            && now - value.draining_since >= lifecycle_.drain_timeout;
        if (expired && value.capture_association != 0) {
            capture_routes_.erase(value.capture_association);
        }
        return expired;
    }), sessions_.end());

    auto const removed = before - sessions_.size();
    connection_count_ -= removed;
    completed_sessions_ += removed;
    if (removed != 0) snapshots_dirty_ = true;
    bool transport_cleanup = removed != 0;

    // A verified upstream can outlive a client that disappeared before accept.
    // Bound that orphan state by the same handshake timeout.
    for (auto iterator = staged_upstreams_.begin(); iterator != staged_upstreams_.end();) {
        if (now - iterator->second.created < lifecycle_.handshake_timeout) {
            ++iterator;
            continue;
        }
        ++handshake_timeouts_;
        dispatcher_bindings_.erase(iterator->first);
        if (iterator->second.connection) iterator->second.connection->close(1);
        transport_cleanup = true;
        iterator = staged_upstreams_.erase(iterator);
    }

    // A disconnected downstream may never resume its certificate callback.
    // All pending transport state is worker-owned and can be released here.
    for (auto iterator = certificate_jobs_.begin(); iterator != certificate_jobs_.end();) {
        if (now - iterator->second.created < lifecycle_.handshake_timeout) {
            ++iterator;
            continue;
        }
        ++handshake_timeouts_;
        dispatcher_bindings_.erase(iterator->first);
        if (iterator->second.upstream) iterator->second.upstream->close(1);
        transport_cleanup = true;
        iterator = certificate_jobs_.erase(iterator);
    }

    // Failed or abandoned handshakes must not retain their pre-policy packet
    // journal indefinitely. Live accepted sessions own their journal directly.
    for (auto iterator = pending_captures_.begin(); iterator != pending_captures_.end();) {
        if (now - iterator->second.updated < lifecycle_.handshake_timeout) {
            ++iterator;
            continue;
        }
        capture_routes_.erase(iterator->first);
        auto const association = iterator->first;
        for (auto binding = dispatcher_bindings_.begin();
             binding != dispatcher_bindings_.end();) {
            if (binding->second.association == association) {
                binding = dispatcher_bindings_.erase(binding);
            }
            else ++binding;
        }
        iterator = pending_captures_.erase(iterator);
    }
    for (auto iterator = capture_routes_.begin(); iterator != capture_routes_.end();) {
        if (iterator->second.expired()) iterator = capture_routes_.erase(iterator);
        else ++iterator;
    }
    for (auto iterator = dispatcher_bindings_.begin();
         iterator != dispatcher_bindings_.end();) {
        if (now - iterator->second.updated >= lifecycle_.handshake_timeout) {
            iterator = dispatcher_bindings_.erase(iterator);
        } else {
            ++iterator;
        }
    }
    return transport_cleanup;
}

// Read on the owning worker; publish only copied values to the management plane.
static tls_snapshot snapshot_tls(SSL* ssl) {
    tls_snapshot result;
    if (!ssl) return result;

    result.available = true;
    result.established = SSL_is_init_finished(ssl) != 0;
    result.state = SSL_state_string_long(ssl);
    if (const auto* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) {
        result.server_name = name;
    }

    result.verify_peer = (SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER) != 0;
    result.verify_result = SSL_get_verify_result(ssl);
    result.verify_error = X509_verify_cert_error_string(result.verify_result);
    if (result.established) {
        if (auto* verifier = certificate_verifier::get(ssl)) {
            if (verifier->verdict() == 0) result.verify_error = "certificate policy pending";
            else if (verifier->verdict() < 0) result.verify_error = "certificate policy rejected";
        }
    }

    // Before completion, OpenSSL may report a version that was not negotiated.
    if (!result.established) return result;

    result.resumed = SSL_session_reused(ssl) != 0;
    if (const auto* cipher = SSL_get_current_cipher(ssl)) {
        result.cipher = SSL_CIPHER_get_name(cipher);
    }

    result.version = "unknown";
    const auto* session = SSL_get_session(ssl);
    if (!session) return result;

    // SSL_get_version() describes the QUIC transport, not its TLS handshake.
    const auto version = SSL_SESSION_get_protocol_version(session);
    result.version = version == TLS1_3_VERSION
        ? "TLSv1.3" : "unknown (" + std::to_string(version) + ")";

    result.has_ticket = SSL_SESSION_has_ticket(session) != 0;
    if (result.has_ticket) {
        result.ticket_lifetime_hint = SSL_SESSION_get_ticket_lifetime_hint(session);
    }
    return result;
}

std::string listener_service::handshake_phase(session const& value) const {
    if (value.state == session_state::draining) return value.last_handshake_phase;
    if (value.state == session_state::active) return "complete";
    if (value.downstream) {
        auto const job = certificate_jobs_.find(value.downstream->handle_native());
        if (job != certificate_jobs_.end()) {
            switch (job->second.state) {
            case certificate_state::queued: return "upstream-connect";
            case certificate_state::upstream_handshake:
                // The shared engine can finish TLS in the output pass, after
                // this job ran. Admission still waits for its next worker turn.
                return job->second.upstream && job->second.upstream->handshake_complete()
                    ? "upstream-certificate-check" : "upstream-handshake";
            case certificate_state::certificate_check: return "upstream-certificate-check";
            case certificate_state::certificate_ready: return "certificate-install";
            case certificate_state::failed: return "upstream-failed";
            }
        }
    }
    if (value.upstream && !value.upstream->handshake_complete()) return "upstream-handshake";
    if (value.upstream) {
        auto* verifier = certificate_verifier::get(value.upstream->handle_native());
        if (verifier && verifier->verdict() == 0) return "upstream-certificate-check";
    }
    if (value.downstream && !value.downstream->handshake_complete()) return "downstream-handshake";
    return value.upstream ? "bridge-setup" : "upstream-connect";
}

void listener_service::publish_session_snapshots(
    std::chrono::steady_clock::time_point now) {
    // Rendering rates, policies and TLS details is management work, not part
    // of forwarding each packet. Reuse this round's timestamp; never sleep or
    // delay I/O to sample it. Admission, handshake and shutdown bypass the cap.
    if (!snapshots_dirty_ && now < next_snapshot_) return;
    next_snapshot_ = now + std::chrono::milliseconds(100);
    snapshots_dirty_ = false;

    std::vector<session_snapshot> result;
    result.reserve(sessions_.size());
    for (auto const& linked : sessions_) {
        session_snapshot item;
        item.id = linked.id;
        item.handshake_phase = handshake_phase(linked);
        item.end_reason = linked.end_reason;
        item.state = linked.state == session_state::handshake ? "handshake"
                   : linked.state == session_state::active ? "active" : "draining";
        if (linked.state == session_state::draining) {
            item.downstream_tls = linked.draining_downstream_tls;
            item.upstream_tls = linked.draining_upstream_tls;
        }
        item.client = endpoint_text(linked.client_endpoint);
        item.target = endpoint_text(linked.target_endpoint);
        if (linked.downstream) {
            item.server_name = linked.downstream->server_name();
            item.downstream_alpn = linked.downstream->negotiated_alpn();
            item.downstream_tls = linked.state == session_state::draining
                ? linked.draining_downstream_tls : snapshot_tls(linked.downstream->handle_native());
        }
        if (item.target == "-") {
            auto const& host = upstream_host_.empty() ? item.server_name : upstream_host_;
            if (!host.empty()) item.target = host + ":" + std::to_string(upstream_port_);
        }
        auto upstream = linked.upstream;
        if (!upstream && linked.downstream) {
            auto const job = certificate_jobs_.find(linked.downstream->handle_native());
            if (job != certificate_jobs_.end()) upstream = job->second.upstream;
        }
        if (upstream) {
            item.upstream_alpn = upstream->negotiated_alpn();
            item.upstream_tls = linked.state == session_state::draining
                ? linked.draining_upstream_tls : snapshot_tls(upstream->handle_native());
        }
        item.age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - linked.created).count();
        item.idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - linked.last_activity).count();
        item.forwarded_bytes = linked.forwarded_bytes;
        item.stream_summary = linked.proxy ? linked.proxy->summary() : linked.stream_summary;
        item.sift_classifications = linked.proxy
            ? linked.proxy->sift_classifications() : linked.sift_classifications;
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
                                      std::uint64_t protocol_error, const char* reason) {
    if (value.state == session_state::draining) return;

    value.last_handshake_phase = handshake_phase(value);
    value.end_reason = reason;
    if (value.downstream) {
        auto const key = value.downstream->handle_native();
        if (auto pending = certificate_jobs_.find(key); pending != certificate_jobs_.end()) {
            if (pending->second.state == certificate_state::failed) value.end_reason = "upstream certificate preparation failed";
            if (!value.upstream) value.upstream = std::move(pending->second.upstream);
            certificate_jobs_.erase(pending);
        }
        if (auto staged = staged_upstreams_.find(key); staged != staged_upstreams_.end()) {
            if (!value.upstream) value.upstream = std::move(staged->second.connection);
            staged_upstreams_.erase(staged);
        }
        dispatcher_bindings_.erase(key);
    }

    if(value.downstream)
        value.draining_downstream_tls = snapshot_tls(value.downstream->handle_native());
    if(value.upstream)
        value.draining_upstream_tls = snapshot_tls(value.upstream->handle_native());

    value.draining_downstream_tls.ended = true;
    value.draining_upstream_tls.ended = true;

    // Sample outcomes before close retires the handshake evidence.
    if(value.downstream) hook_outcome(value.setup.get(), value.downstream->handle_native(),
                                      true, "QUIC handshake ended before completion");
    if(value.upstream) hook_outcome(value.setup.get(), value.upstream->handle_native(),
                                    false, "QUIC handshake ended before completion");
    logging::session().dia("session %llu draining protocol-error=%llu forwarded=%llu",
                           static_cast<unsigned long long>(value.id),
                           static_cast<unsigned long long>(protocol_error),
                           static_cast<unsigned long long>(value.forwarded_bytes));
    value.state = session_state::draining;
    snapshots_dirty_ = true;
    value.draining_since = now;
    if (value.proxy) {
        value.stream_summary = value.proxy->summary();
        // No streams forward data once the bridge has shut down.
        value.stream_summary.upload_bps = 0;
        value.stream_summary.download_bps = 0;
        value.proxy->shutdown();
        value.sift_classifications = value.proxy->sift_classifications();
    }
    value.proxy.reset();
    if (value.downstream) value.downstream->close(protocol_error);
    if (value.upstream) value.upstream->close(protocol_error);
}

void listener_service::cleanup_sessions() {
    completed_sessions_ += sessions_.size();
    for (auto& linked : sessions_) {
        if(linked.proxy) linked.proxy->shutdown();
        if (linked.downstream) linked.downstream->close();
        if (linked.upstream) linked.upstream->close();
    }
    sessions_.clear();
    staged_upstreams_.clear();
    certificate_jobs_.clear();
    pending_captures_.clear();
    capture_routes_.clear();
    dispatcher_bindings_.clear();
    {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);
        snapshots_.clear();
    }
    connection_count_ = 0;
}
#endif

bool detail::same_certificate_callback_identity(
    std::string const& staged_server_name, std::uint64_t staged_generation,
    std::string const& current_server_name, std::uint64_t current_generation) {
    return staged_server_name == current_server_name
        && staged_generation != 0
        && staged_generation == current_generation;
}

bool detail::same_dispatcher_callback_association(
    std::uint64_t staged_association, std::uint64_t current_association) {
    return staged_association != 0 && staged_association == current_association;
}

#if SMITHPROXY_OPENSSL_QUIC
int listener_service::client_hello_callback(SSL* ssl, int* alert, void* argument) {
    auto* service = static_cast<listener_service*>(argument);
    try {
        if(service && service->prepare_tls_policy(ssl)) return SSL_CLIENT_HELLO_SUCCESS;
    } catch (...) {
        ++stats.errors.listener_client_hello_callback_exception;
        // No C++ exception may cross OpenSSL's callback boundary.
        log().err("QUIC TLS policy preparation raised an exception");
    }
    if(alert) *alert = SSL_AD_ACCESS_DENIED;
    return SSL_CLIENT_HELLO_ERROR;
}

// Resolve policy once for this ClientHello and scope its session tickets to the
// certificate rules. False rejects admission; callback re-entry reuses the snapshot.
bool listener_service::prepare_tls_policy(SSL* downstream) {
    const bool associated = bind_capture_session(downstream) != 0;
    if (!setup_factory_) {
        return true; // Standalone transport fixtures have no policy provider.
    }
    if (!associated) {
        return !transparent_; // Direct socket fixtures have no dispatcher tuple.
    }

    auto& binding = dispatcher_bindings_.at(downstream);
    if (binding.setup) {
        return true;
    }

    auto const [source_host, source_port] = endpoint_parts(binding.client);
    auto const [target_host, target_port] = endpoint_parts(binding.destination);
    if (source_host.empty() || target_host.empty()) {
        return false;
    }

    auto setup = setup_factory_(source_host, source_port);
    if (setup) {
        setup->ingress_ifindex(binding.ingress_ifindex);
    }
    auto policy = setup ? setup->tls_policy(target_host, target_port) : std::nullopt;
    if (!policy) {
        return false;
    }

    // QUIC requires TLS 1.3 key exchange and an application protocol. Refuse
    // incompatible profiles rather than silently relaxing either restriction.
    if (!policy->use_pfs || policy->alpn_block) {
        log().war("QUIC TLS profile rejects target=%s:%s: pfs=%d alpn-block=%d",
                  target_host.c_str(), target_port.c_str(), policy->use_pfs, policy->alpn_block);
        return false;
    }

    // Tickets issued under a certificate exception must not bypass a stricter
    // profile (including custom-only identity selection) after policy changes.
    std::array<unsigned char, 13> const certificate_scope {{
        'Q', 'C', 1,
        static_cast<unsigned char>(policy->allow_self_signed),
        static_cast<unsigned char>(policy->allow_invalid_certs),
        static_cast<unsigned char>(policy->allow_untrusted_issuers),
        static_cast<unsigned char>(policy->ct_enable),
        static_cast<unsigned char>(policy->ocsp_stapling),
        static_cast<unsigned char>(policy->ocsp_stapling_mode),
        static_cast<unsigned char>(policy->ocsp_mode),
        static_cast<unsigned char>(policy->sni_based_cert),
        static_cast<unsigned char>(policy->ip_based_cert),
        static_cast<unsigned char>(policy->only_custom_certs)
    }};
    if (SSL_set_session_id_context(downstream, certificate_scope.data(), certificate_scope.size()) != 1) {
        return false;
    }

    if (policy->disable_reuse) {
        // Stop new tickets and isolate this handshake from tickets previously
        // issued under a permissive profile in the shared listener context.
        static constexpr unsigned char no_reuse[] = "smithproxy-quic-no-reuse";
        if (SSL_set_num_tickets(downstream, 0) != 1 ||
           SSL_set_session_id_context(downstream, no_reuse, sizeof(no_reuse) - 1) != 1) {
            log().war("QUIC TLS profile cannot disable downstream session reuse");
            return false;
        }
    }

    binding.setup = std::move(setup);
    return true;
}

int listener_service::bind_capture_session(SSL* downstream) {
    if (!downstream || !listener_) return 0;
    auto const association = listener_->current_association();
    auto const existing = dispatcher_bindings_.find(downstream);
    if (existing != dispatcher_bindings_.end() &&
        detail::same_dispatcher_callback_association(
            existing->second.association, association)) {
        // OpenSSL may report ClientHello more than once while the pending
        // certificate callback is suspended. It is still the same handshake;
        // changing its generation here makes the resumed callback look like
        // allocator reuse and fails every otherwise valid connection closed.
        return 1;
    }
    if (dispatcher_bindings_.size() >= limits_.max_sessions &&
        existing == dispatcher_bindings_.end()) {
        log().war("QUIC dispatcher association limit %zu reached", limits_.max_sessions);
        return 0;
    }
    auto const generation = next_dispatcher_binding_generation_++;
    if (next_dispatcher_binding_generation_ == 0) ++next_dispatcher_binding_generation_;
    dispatcher_bindings_[downstream] = dispatcher_binding {
        listener_->current_ingress_ifindex(),
        listener_->current_peer(), listener_->current_local(),
        association, generation, std::chrono::steady_clock::now(), {}};
    if (association == 0) {
        log().war("downstream ClientHello has no QUIC dispatcher association");
        return 0;
    }
    // Connection IDs can rotate after the handshake. Learn authenticated CID
    // frames from this SSL, so two destinations sharing a client IP:port never
    // depend on an ambiguous peer-only route lookup.
    return listener_->bind_connection_route(downstream) ? 1 : 0;
}

int listener_service::certificate_callback(SSL* ssl, void* argument) {
    auto* service = static_cast<listener_service*>(argument);
    if (!service || !ssl) {
        ++stats.errors.listener_certificate_callback_missing_context;
        return 0;
    }
    try {
        return service->prepare_verified_certificate(ssl);
    } catch (...) {
        ++stats.errors.listener_certificate_callback_exception;
        return 0; // Fail closed; never unwind through a TLS C callback.
    }
}

int listener_service::prepare_verified_certificate(SSL* downstream) {
    if (!downstream) return 0;
    auto const* raw_name = SSL_get_servername(downstream, TLSEXT_NAMETYPE_host_name);
    std::string const server_name = raw_name ? raw_name : "";
    auto const binding = dispatcher_bindings_.find(downstream);
    auto const generation = binding == dispatcher_bindings_.end()
        ? 0 : binding->second.generation;
    if (auto staged = staged_upstreams_.find(downstream);
        staged != staged_upstreams_.end()) {
        if (detail::same_certificate_callback_identity(
                staged->second.server_name, staged->second.callback_generation,
                server_name, generation)) {
            return 1;
        }
        staged_upstreams_.erase(staged);
    }

    if (auto found = certificate_jobs_.find(downstream);
        found != certificate_jobs_.end()) {
        auto& job = found->second;
        if (!detail::same_certificate_callback_identity(
                job.server_name, job.callback_generation,
                server_name, generation)) {
            if (job.upstream) job.upstream->close(1);
            certificate_jobs_.erase(found);
            return 0;
        }

        if (job.state == certificate_state::queued
            || job.state == certificate_state::upstream_handshake
            || job.state == certificate_state::certificate_check) return -1;
        if (job.state == certificate_state::failed) return 0;
        if (!install_verified_certificate(downstream, job.result)) {
            ++upstream_failures_;
            job.state = certificate_state::failed;
            return 0;
        }
        auto upstream = std::move(job.upstream);
        auto setup = job.setup;
        auto const client = job.client;
        auto const destination = job.destination;
        certificate_jobs_.erase(found);

        // Only transfer ownership here; never drive another SSL object
        // reentrantly from the downstream certificate callback.
        staged_upstreams_.emplace(downstream, staged_upstream {
            std::move(setup), client, destination, server_name, generation,
            std::chrono::steady_clock::now(), std::move(upstream) });
        return 1;
    }

    if (generation == 0) return 0; // Closed or unbound downstream: never restart B.
    if (!raw_name || *raw_name == '\0') {
        log().war("downstream handshake rejected: SNI is missing");
        return 0;
    }
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
        // This first callback is synchronous with the datagram dispatcher.
        // Reading its active destination avoids a peer-only lookup which could
        // alias concurrent connections using the same client endpoint.
        if (listener_) destination = listener_->current_local();
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
    logging::mitm().deb("starting certificate job sni='%s' peer=%s target=%s",
                        server_name.c_str(), endpoint_text(peer_endpoint).c_str(),
                        endpoint_text(destination).c_str());
    auto setup = binding == dispatcher_bindings_.end() ? nullptr : binding->second.setup;
    if(!setup && setup_factory_) {
        auto const [host, port] = endpoint_parts(peer_endpoint);
        setup = setup_factory_(host, port);
    }

    certificate_jobs_.emplace(downstream, certificate_job {
        std::move(setup), {}, peer_endpoint, destination, server_name, generation,
        std::chrono::steady_clock::now(), {}, certificate_state::queued });
    return -1;
}

// Advance each pending certificate request on the listener thread. A job keeps
// its upstream connection for forwarding; only revocation checks leave this thread.
// OpenSSL's downstream certificate callback consumes the ready/failed state later.
bool listener_service::progress_certificate_jobs() {
    bool progress = false;
    for (auto& [downstream, job] : certificate_jobs_) {
        if (job.state == certificate_state::certificate_ready
            || job.state == certificate_state::failed) {
            // Preserve early streams in OpenSSL until the bridge takes over.
            if (job.upstream) job.upstream->progress_transport();
            continue;
        }
        if (std::chrono::steady_clock::now() - job.created >= lifecycle_.handshake_timeout) {
            // The session timeout owns the transition and its counter.
            // Unaccepted jobs are expired by reap_expired().
            continue;
        }
        if (!job.upstream) {
            progress = true; // A new B channel needs its first shared engine pass.
            job.upstream = transparent_
                ? connect_upstream(job.destination, job.server_name, job.setup.get())
                : connect_upstream(job.server_name, job.setup.get());
        }
        if (!job.upstream) {
            ++upstream_failures_;
            job.state = certificate_state::failed;
            progress = true; // Resume the downstream callback to report failure.
            continue;
        }

        job.state = certificate_state::upstream_handshake;
        job.upstream->progress_transport();
        if (job.upstream->closed()) {
            logging::info().war("QUIC upstream handshake rejected sni='%s' verify=%ld",
                                job.server_name.c_str(), SSL_get_verify_result(job.upstream->handle_native()));
            hook_outcome(job.setup.get(), job.upstream->handle_native(), false,
                         "QUIC upstream handshake failed");
            ++upstream_failures_;
            job.state = certificate_state::failed;
            progress = true; // Resume the downstream callback to report failure.
            continue;
        }
        if (!job.upstream->handshake_complete()) {
            continue;
        }

        // TLS completion alone is not admission: OCSP/CRL policy may still be
        // pending in the pool. Keep the downstream certificate callback waiting.
        auto* verifier = certificate_verifier::get(job.upstream->handle_native());
        int const verdict = verifier ? verifier->progress(job.upstream->handle_native()) : 1;
        if (verdict == 0) {
            job.state = certificate_state::certificate_check;
            continue;
        }
        if (verdict < 0) {
            logging::verify().war("QUIC certificate policy rejected sni='%s'", job.server_name.c_str());
            job.upstream->close(1);
            ++upstream_failures_;
            job.state = certificate_state::failed;
            progress = true; // Resume the downstream callback to report failure.
            continue;
        }
        if (hook_outcome(job.setup.get(), job.upstream->handle_native(), false)) {
            job.result = verify_and_spoof(job.upstream, job.destination, job.server_name);
        }
        if (!job.result.certificate) {
            ++upstream_failures_;
        }
        progress = true; // Resume the suspended downstream certificate callback.
        job.state = job.result.certificate ? certificate_state::certificate_ready
                                           : certificate_state::failed;
    }
    return progress;
}

// Select the downstream identity only after authenticating the retained upstream.
// Prefer a configured identity, then a cached/generated MITM certificate. An empty
// result rejects the handshake and closes the upstream rather than forwarding data.
listener_service::verified_certificate listener_service::verify_and_spoof(
    std::shared_ptr<transport_connection> const& upstream,
    datagram_endpoint destination, std::string const& server_name) {
    verified_certificate verified;
    auto* verifier = certificate_verifier::get(upstream->handle_native());
    if (!upstream->handshake_complete()
        || (verifier ? verifier->progress(upstream->handle_native()) != 1
            : SSL_get_verify_result(upstream->handle_native()) != X509_V_OK)) {
        logging::verify().war("upstream verification failed sni='%s' target=%s verify=%ld",
                              server_name.c_str(), endpoint_text(destination).c_str(),
                              SSL_get_verify_result(upstream->handle_native()));
        upstream->close(1);
        return verified;
    }
    if (upstream->negotiated_alpn() != "h3") {
        logging::alpn().war("upstream ALPN rejected sni='%s' negotiated='%s'",
                            server_name.c_str(), upstream->negotiated_alpn().c_str());
        upstream->close(1);
        return verified;
    }

    socle::raw::var<X509*> peer_certificate {SSL_get1_peer_certificate(upstream->handle_native()),
        [](auto*& value) { X509_free(value); }};
    auto* certificate = peer_certificate.value; // Borrowed for identity checks and cache lookup.
    if (!certificate) {
        upstream->close(1);
        return verified;
    }
    std::array<unsigned char, sizeof(in6_addr)> binary_address {};
    auto const numeric_identity =
        ::inet_pton(AF_INET, server_name.c_str(), binary_address.data()) == 1
        || ::inet_pton(AF_INET6, server_name.c_str(), binary_address.data()) == 1;
    auto const identity_matches = numeric_identity
        ? X509_check_ip_asc(certificate, server_name.c_str(), 0)
        : X509_check_host(certificate, server_name.c_str(), server_name.size(), 0, nullptr);
    if (identity_matches != 1) {
        logging::verify().war("upstream identity mismatch sni='%s'", server_name.c_str());

        upstream->close(1);
        return verified;
    }

    SpoofOptions options;
    options.sni = server_name;
    options.self_signed = verifier && !verifier->trusted();
    auto& factory = SSLFactory::factory();
    auto const store_key = SSLFactory::make_store_key(certificate, options);
    auto lock = std::scoped_lock(factory.lock());

    // The factory owns its cached objects. Hold independent references so the
    // selected identity survives cache eviction and the downstream handshake.
    auto retain = [&verified](X509* cert, EVP_PKEY* key) {
        if (!cert || !key || X509_up_ref(cert) != 1) {
            return false;
        }
        if (EVP_PKEY_up_ref(key) != 1) {
            X509_free(cert);
            return false;
        }
        verified.certificate = std::shared_ptr<X509>(cert, X509_free);
        verified.private_key = std::shared_ptr<EVP_PKEY>(key, EVP_PKEY_free);
        return true;
    };
    // Match TLS selection order: SNI first, destination IP second. Custom-only
    // policy must fail here if neither source provides a usable identity.
    auto const policy = verifier ? verifier->policy() : proxymaker::QuicTlsPolicy {};
    auto custom = [&]() -> std::optional<const CertificateChainCtx> {
        if (policy.sni_based_cert) {
            auto match = factory.find_custom("sni:" + server_name);
            if (match) {
                return match;
            }
        }
        if (policy.ip_based_cert && destination.valid()) {
            return factory.find_custom("ip:" + endpoint_parts(destination).first);
        }
        return std::nullopt;
    }();
    if (custom && retain(custom->chain.cert, custom->chain.key)) {
        for (auto* issuer : custom->chain.issuers) {
            if (!issuer) {
                continue;
            }
            if (X509_up_ref(issuer) != 1) {

                upstream->close(1);
                return {};
            }
            verified.issuers.emplace_back(issuer, X509_free);
        }

        return verified;
    }
    if (policy.only_custom_certs) {
        logging::verify().war("QUIC certificate policy rejected sni='%s': custom identity required", server_name.c_str());

        upstream->close(1);
        return {};
    }
    auto cached = factory.find_mitm(store_key);
    bool ready = cached && retain(cached->chain.cert, cached->chain.key);
    if (!ready) {
        auto forged = factory.spoof(certificate, options.self_signed, nullptr);
        if (forged && forged->chain.cert && forged->chain.key) {
            ready = retain(forged->chain.cert, forged->chain.key);
            // ptr_cache uses allocator state tied to the allocating thread.
            // Keep the retained result session-local: shared cache teardown
            // can still occur on a different worker from its allocation.
            X509_free(forged->chain.cert);
            forged->nullify(); // SSLFactory::spoof() returns def_sr_key as borrowed.
        }
    }

    if (!ready) {
        logging::mitm().err("certificate spoof failed sni='%s'", server_name.c_str());
        upstream->close(1);
        return {};
    }
    logging::mitm().deb("certificate ready sni='%s' target=%s", server_name.c_str(),
                        endpoint_text(destination).c_str());
    // The worker retains this authenticated connection for application data.
    return verified;
}

// Install the selected leaf, key and intermediates on the downstream SSL.
// SSL takes its own references; false prevents completing a partial identity.
bool listener_service::install_verified_certificate(
    SSL* downstream, verified_certificate const& verified) {
    bool const identity_available = downstream && verified.certificate && verified.private_key;
    if (!identity_available) {
        ++stats.errors.listener_certificate_identity_missing;
        return false;
    }

    bool const leaf_installed = SSL_use_certificate(downstream, verified.certificate.get()) == 1
        && SSL_use_PrivateKey(downstream, verified.private_key.get()) == 1;
    bool const chain_ready = leaf_installed && SSL_check_private_key(downstream) == 1
        && SSL_clear_chain_certs(downstream) == 1;
    if (!chain_ready) {
        ++stats.errors.listener_certificate_install_failed;
        return false;
    }
    for (auto const& issuer : verified.issuers) {
        if (SSL_add1_chain_cert(downstream, issuer.get()) != 1) {
            ++stats.errors.listener_certificate_issuer_failed;
            return false;
        }
    }
    return true;
}

std::shared_ptr<transport_connection> listener_service::connect_upstream(
    std::string const& host, proxymaker::SessionSetup* setup) {
    if (host.empty() || !client_context_) return nullptr;
    addrinfo hints {};
    hints.ai_family = address_family_;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo* addresses = nullptr;
    auto const port = std::to_string(upstream_port_);
    auto const& address_host = upstream_host_.empty() ? host : upstream_host_;
    if (::getaddrinfo(address_host.c_str(), port.c_str(), &hints, &addresses) != 0) {
        return nullptr;
    }

    std::shared_ptr<transport_connection> result;
    for (auto* current = addresses; current && !result; current = current->ai_next) {
        std::string error;
        datagram_endpoint target;
        std::memcpy(&target.address, current->ai_addr, current->ai_addrlen);
        target.size = current->ai_addrlen;
        auto const [target_host, target_port] = endpoint_parts(target);
        auto connection = proxymaker::connect(setup, target_host, target_port, [&] {
            return listener_->connect(client_context_.get(), current->ai_addr,
                                      current->ai_addrlen, host, &error, setup, [&](SSL* ssl) {
                auto policy = setup ? setup->tls_policy(target_host, target_port)
                    : std::optional {proxymaker::QuicTlsPolicy {}};
                return policy && (!verify_upstream_ || certificate_verifier::install(ssl, *policy));
            });
        });
        if (connection) result = std::shared_ptr<transport_connection>(std::move(connection));
    }
    ::freeaddrinfo(addresses);
    return result;
}

std::shared_ptr<transport_connection> listener_service::connect_upstream(
    datagram_endpoint const& target, std::string const& server_name,
    proxymaker::SessionSetup* setup) {
    if (!target.valid() || server_name.empty() || !client_context_) return nullptr;
    std::string error;
    auto const [host, port] = endpoint_parts(target);
    auto connection = proxymaker::connect(setup, host, port, [&] {
        return listener_->connect(
            client_context_.get(), reinterpret_cast<sockaddr const*>(&target.address),
            target.size, server_name, &error, setup, [&](SSL* ssl) {
                auto policy = setup ? setup->tls_policy(host, port)
                    : std::optional {proxymaker::QuicTlsPolicy {}};
                return policy && (!verify_upstream_ || certificate_verifier::install(ssl, *policy));
            });
    });
    return connection
        ? std::shared_ptr<transport_connection>(std::move(connection))
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

void listener_service::drain() {
    draining_ = true;
#if SMITHPROXY_OPENSSL_QUIC
    if (wake_fd_ >= 0) (void)::eventfd_write(wake_fd_, 1);
#endif
}

} // namespace sx::quic
