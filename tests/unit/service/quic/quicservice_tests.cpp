#include <gtest/gtest.h>

#include "service/quic/quicservice.hpp"
#include "service/quic/worker_dispatcher.hpp"

#include "proxy/multiflow/mfflowcom.hpp"
#include <sslcertstore.hpp>
#include <proxy/quic_observer.hpp>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <thread>

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace quic = sx::quic;

TEST(QuicCertificateCallbackIdentity, RejectsReusedBorrowedHandles) {
    EXPECT_TRUE(quic::detail::same_certificate_callback_identity(
        "origin.example", 41, "origin.example", 41));
    EXPECT_FALSE(quic::detail::same_certificate_callback_identity(
        "other.example", 41, "origin.example", 41));
    EXPECT_FALSE(quic::detail::same_certificate_callback_identity(
        "origin.example", 40, "origin.example", 41));
    EXPECT_FALSE(quic::detail::same_certificate_callback_identity(
        "origin.example", 0, "origin.example", 0));
}

TEST(QuicCertificateCallbackIdentity, PreservesGenerationAcrossCallbackReentry) {
    EXPECT_TRUE(quic::detail::same_dispatcher_callback_association(17, 17));
    EXPECT_FALSE(quic::detail::same_dispatcher_callback_association(17, 18));
    EXPECT_FALSE(quic::detail::same_dispatcher_callback_association(17, 0));
    EXPECT_FALSE(quic::detail::same_dispatcher_callback_association(0, 0));
}

class QuicListenerService : public ::testing::Test {
protected:
    static inline std::string saved_ca_file;
    static inline std::string saved_ca_path;
    static inline bool saved_initialized = false;

    static void SetUpTestSuite() {
        auto& factory = SSLFactory::factory();
        saved_ca_file = factory.ca_file();
        saved_ca_path = factory.ca_path();
        saved_initialized = factory.is_initialized.load();
        factory.destroy();
        factory.ca_file() = "etc/certs/default/ca-cert.pem";
        factory.ca_path().clear();
        ASSERT_TRUE(factory.load_trust_store());
    }

    static void TearDownTestSuite() {
        auto& factory = SSLFactory::factory();
        factory.destroy();
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
        if (saved_initialized) factory.init();
    }
};

TEST_F(QuicListenerService, PreparesAndStopsLoopbackListener) {
    quic::listener_service service(0,
                                   "etc/certs/default/srv-cert.pem",
                                   "etc/certs/default/srv-key.pem",
                                   false, 443, false);

    if (!quic::openssl_quic_available()) {
        EXPECT_FALSE(service.prepare());
        return;
    }

    ASSERT_TRUE(service.prepare()) << service.last_error();
    EXPECT_TRUE(service.ready());

    std::thread runner([&service]() { service.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    service.stop();
    runner.join();
    EXPECT_TRUE(service.last_error().empty()) << service.last_error();
    EXPECT_EQ(service.connection_count(), 0U);
}

TEST_F(QuicListenerService, DetailsWithoutRunningListenerCompleteImmediately) {
    quic::listener_service service(0, "", "", false, 443, false);
    auto details = service.request_session_details([](MitmProxy*) {
        return std::optional<std::string>{"unexpected"};
    });
    ASSERT_EQ(details.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);
    EXPECT_TRUE(details.get().empty());
}

TEST_F(QuicListenerService, IdleListenerDrainsWithoutForcedStop) {
    quic::listener_service service(0,
                                   "etc/certs/default/srv-cert.pem",
                                   "etc/certs/default/srv-key.pem",
                                   false, 443, false);
    if (!quic::openssl_quic_available()) {
        EXPECT_FALSE(service.prepare());
        return;
    }

    if (!service.prepare() && service.last_error().find("Operation not permitted") != std::string::npos)
        GTEST_SKIP() << service.last_error();
    ASSERT_TRUE(service.ready()) << service.last_error();
    std::thread runner([&service]() { service.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    service.drain();
    runner.join();
    EXPECT_TRUE(service.last_error().empty()) << service.last_error();
    EXPECT_EQ(service.connection_count(), 0U);
}

#if SMITHPROXY_OPENSSL_QUIC
TEST_F(QuicListenerService, IdleListenerSleepsUntilExplicitWakeup) {
    quic::listener_service service(0,
                                   "etc/certs/default/srv-cert.pem",
                                   "etc/certs/default/srv-key.pem",
                                   false, 443, false);
    ASSERT_TRUE(service.prepare()) << service.last_error();

    std::chrono::nanoseconds worker_cpu {};
    std::thread runner([&]() {
        timespec before {};
        timespec after {};
        ASSERT_EQ(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &before), 0);
        service.run();
        ASSERT_EQ(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &after), 0);
        worker_cpu = std::chrono::seconds(after.tv_sec - before.tv_sec)
            + std::chrono::nanoseconds(after.tv_nsec - before.tv_nsec);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    auto const stop_started = std::chrono::steady_clock::now();
    service.stop();
    runner.join();

    EXPECT_LT(worker_cpu, std::chrono::milliseconds(20));
    EXPECT_LT(std::chrono::steady_clock::now() - stop_started,
              std::chrono::milliseconds(100));
}
#endif

#if SMITHPROXY_OPENSSL_QUIC
namespace {

std::size_t open_descriptor_count() {
    std::error_code error;
    std::size_t count = 0;
    for(std::filesystem::directory_iterator entry("/proc/self/fd", error), end;
        !error && entry != end; entry.increment(error)) {
        ++count;
    }
    return error ? 0 : count;
}

int select_h3_for_origin(SSL*, const unsigned char** output, unsigned char* output_size,
                         const unsigned char* input, unsigned input_size, void*) {
    static constexpr unsigned char supported[] = { 2, 'h', '3' };
    return SSL_select_next_proto(const_cast<unsigned char**>(output), output_size,
                                 supported, sizeof(supported), input, input_size)
            == OPENSSL_NPN_NEGOTIATED
        ? SSL_TLSEXT_ERR_OK
        : SSL_TLSEXT_ERR_NOACK;
}

bool nonblocking(int fd) {
    auto const flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

} // namespace

TEST_F(QuicListenerService, FailedPrepareDoesNotLeakDescriptorsAcrossRetries) {
    const int occupied = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(occupied, 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    ASSERT_EQ(::bind(occupied, reinterpret_cast<sockaddr*>(&address),
                     sizeof(address)), 0);
    socklen_t address_size = sizeof(address);
    ASSERT_EQ(::getsockname(occupied, reinterpret_cast<sockaddr*>(&address),
                            &address_size), 0);

    quic::listener_service service(
        ntohs(address.sin_port), "etc/certs/default/srv-cert.pem",
        "etc/certs/default/srv-key.pem", false, 443, false);
    const auto before = open_descriptor_count();
    ASSERT_NE(before, 0U);
    for(int attempt = 0; attempt < 5; ++attempt)
        EXPECT_FALSE(service.prepare());
    EXPECT_EQ(open_descriptor_count(), before);
    ::close(occupied);
}

namespace {

class DeniedSessionSetup final : public sx::proxymaker::SessionSetup {
public:
    std::atomic_uint calls {0};
    std::string host;
    std::string port;

    bool start(std::string const& target_host, std::string const& target_port) override {
        host = target_host;
        port = target_port;
        ++calls;
        return false;
    }
};

} // namespace

TEST_F(QuicListenerService, DeniedSetupPreventsProbeAndForwardingDatagrams) {
    // Exercise both production certificate verification and the direct
    // forwarding path used by isolated transport tests.
    for (bool verify : {true, false}) {
        SCOPED_TRACE(verify);
        auto client_context = quic::make_openssl_quic_context(false);
        ASSERT_NE(client_context, nullptr);
        SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

        const int origin_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ASSERT_GE(origin_fd, 0);
        struct socket_guard {
            int fd;
            ~socket_guard() { close(fd); }
        } origin_guard {origin_fd};

        sockaddr_in origin {};
        origin.sin_family = AF_INET;
        origin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ASSERT_EQ(bind(origin_fd, reinterpret_cast<sockaddr*>(&origin), sizeof(origin)), 0);
        socklen_t size = sizeof(origin);
        ASSERT_EQ(getsockname(origin_fd, reinterpret_cast<sockaddr*>(&origin), &size), 0);

        auto setup = std::make_shared<DeniedSessionSetup>();
        quic::listener_service proxy(
            0, "etc/certs/default/srv-cert.pem", "etc/certs/default/srv-key.pem",
            false, ntohs(origin.sin_port), verify, {}, {}, "127.0.0.1", {}, false,
            [setup](auto const&, auto const&) { return setup; });
        ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
        std::thread runner([&proxy] { proxy.run(); });
        struct runner_guard {
            quic::listener_service& proxy;
            std::thread& runner;
            ~runner_guard() {
                proxy.stop();
                runner.join();
            }
        } cleanup {proxy, runner};

        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(proxy.bound_port());
        std::string error;
        auto client = quic::connect_openssl_quic(
            client_context.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address),
            "Smithproxy-Server-Certificate", &error);
        ASSERT_NE(client, nullptr) << error;

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (setup->calls.load() == 0 && std::chrono::steady_clock::now() < deadline) {
            client->drain_events();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        ASSERT_EQ(setup->calls.load(), 1U);
        EXPECT_EQ(setup->host, "127.0.0.1");
        EXPECT_EQ(setup->port, std::to_string(ntohs(origin.sin_port)));
        char byte;
        EXPECT_EQ(recv(origin_fd, &byte, 1, MSG_DONTWAIT), -1);
        EXPECT_EQ(errno, EAGAIN);
    }
}

TEST_F(QuicListenerService, CleansUpHandshakeTimeout) {
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(client_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    auto const silent_origin_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(silent_origin_fd, 0);
    sockaddr_in silent_origin {};
    silent_origin.sin_family = AF_INET;
    silent_origin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(silent_origin_fd, reinterpret_cast<sockaddr*>(&silent_origin),
                   sizeof(silent_origin)), 0);
    socklen_t silent_origin_size = sizeof(silent_origin);
    ASSERT_EQ(getsockname(silent_origin_fd, reinterpret_cast<sockaddr*>(&silent_origin),
                          &silent_origin_size), 0);

    quic::lifecycle_options lifecycle;
    lifecycle.handshake_timeout = std::chrono::milliseconds(100);
    lifecycle.drain_timeout = std::chrono::milliseconds(100);
    quic::listener_service proxy(0, "etc/certs/default/srv-cert.pem",
                                 "etc/certs/default/srv-key.pem", false,
                                 ntohs(silent_origin.sin_port), false, lifecycle,
                                 {}, "127.0.0.1");
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    std::thread runner([&proxy]() { proxy.run(); });
    struct cleanup_guard {
        quic::listener_service& service;
        std::thread& runner;
        ~cleanup_guard() {
            service.stop();
            if (runner.joinable()) runner.join();
        }
    } cleanup { proxy, runner };

    sockaddr_in proxy_address {};
    proxy_address.sin_family = AF_INET;
    proxy_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    proxy_address.sin_port = htons(proxy.bound_port());
    std::string error;
    auto external = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr*>(&proxy_address),
        sizeof(proxy_address), "Smithproxy-Server-Certificate", &error);
    ASSERT_NE(external, nullptr) << error;

    bool accepted = false;
    bool saw_ended_handshake = false;
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline
           && (!accepted || proxy.connection_count() != 0)) {
        external->drain_events();
        accepted = accepted || proxy.connection_count() != 0;
        for(const auto& snapshot : proxy.session_diagnostics()) {
            EXPECT_NE(snapshot.state, "active");
            if(snapshot.state != "draining") continue;
            saw_ended_handshake = true;
            EXPECT_TRUE(snapshot.upstream_tls.ended);
            EXPECT_FALSE(snapshot.upstream_tls.established);
            EXPECT_STREQ(snapshot.upstream_tls.handshake_status(), snapshot.upstream_tls.available
                ? "ended before completion" : "not started");
            EXPECT_TRUE(snapshot.downstream_tls.ended);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_TRUE(accepted);
    EXPECT_TRUE(saw_ended_handshake);
    EXPECT_EQ(proxy.connection_count(), 0U);
    auto const diagnostics = proxy.diagnostics();
    EXPECT_EQ(diagnostics.accepted_sessions, 1U);
    EXPECT_EQ(diagnostics.completed_sessions, 1U);
    EXPECT_EQ(diagnostics.handshake_timeouts, 1U);

    external->close();
    proxy.stop();
    runner.join();
    close(silent_origin_fd);
}

TEST_F(QuicListenerService, RejectsSessionsBeyondConfiguredLimit) {
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(client_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    quic::resource_limits limits;
    limits.max_sessions = 0;
    quic::listener_service proxy(0, "etc/certs/default/srv-cert.pem",
                                 "etc/certs/default/srv-key.pem", false,
                                 9, false, {}, limits);
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    std::thread runner([&proxy]() { proxy.run(); });
    struct cleanup_guard {
        quic::listener_service& service;
        std::thread& runner;
        ~cleanup_guard() {
            service.stop();
            if (runner.joinable()) runner.join();
        }
    } cleanup { proxy, runner };

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(proxy.bound_port());
    std::string error;
    auto external = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr*>(&address),
        sizeof(address), "Smithproxy-Server-Certificate", &error);
    // With a zero session limit, rejection may arrive during the initial
    // connect call. A live client object is not an invariant of this test;
    // the server's counters below prove that admission rejected the attempt.

    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline
           && proxy.diagnostics().session_limit_rejections == 0) {
        if(external) external->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    auto const diagnostics = proxy.diagnostics();
    EXPECT_EQ(diagnostics.current_sessions, 0U);
    EXPECT_EQ(diagnostics.accepted_sessions, 0U);
    // QUIC retransmission can cause more than one accepted connection attempt
    // before the client observes rejection. The invariant is that none enter
    // the bounded session table and at least one rejection is accounted.
    EXPECT_GE(diagnostics.session_limit_rejections, 1U);
    if(external) external->close();
}

// A busy application must not make management sampling run at packet frequency.
struct bridge_sampling_probe {
    std::atomic_bool busy = false;
    std::atomic_size_t pumps = 0;
    std::atomic_size_t summaries = 0;
};

// The listener must retain bridge diagnostics independently of bridge lifetime.
class classified_test_bridge final : public sx::multiflow::flow_proxy {
public:
    classified_test_bridge(std::shared_ptr<sx::multiflow::connection> left,
                           std::shared_ptr<sx::multiflow::connection> right,
                           sx::multiflow::proxy_limits limits,
                           std::shared_ptr<bridge_sampling_probe> probe = {})
        : bridge_(std::move(left), std::move(right), limits), probe_(std::move(probe)) {}
    std::size_t pump_once(std::size_t size) override {
        auto const moved = bridge_.pump_once(size);
        if (!probe_) return moved;
        ++probe_->pumps;
        // Keep the worker productive without depending on machine throughput.
        return probe_->busy ? moved + 1 : moved;
    }
    std::size_t pair_count() const override { return bridge_.pair_count(); }
    std::size_t queued_bytes() const override { return bridge_.queued_bytes(); }
    std::size_t limit_rejections() const override { return bridge_.limit_rejections(); }
    std::vector<std::string> sift_classifications() const override {
        return {"app.test", "protocol.http3"};
    }
    std::vector<std::string> render_details(detail_renderer const& render) const override {
        if (auto text = render(nullptr)) return {*text};
        return {};
    }
    sx::multiflow::flow_summary summary() const override {
        if (probe_) ++probe_->summaries;
        sx::multiflow::flow_summary result;
        result.policies = {2, 3};
        result.filters = {"test-filter"};
        result.lored_classifications = {"test-service"};
        result.upload_bps = 1024;
        result.download_bps = 2048;
        result.traffic_available = true;
        return result;
    }
private:
    sx::multiflow::MFProxy bridge_;
    std::shared_ptr<bridge_sampling_probe> probe_;
};

static void exercise_proxy_stream(bool use_workers, bool check_sampling = false) {
    auto origin_context = quic::make_openssl_quic_context(true);
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(origin_context, nullptr);
    ASSERT_NE(client_context, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate_chain_file(origin_context.get(),
                                                 "etc/certs/default/srv-cert.pem"), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey_file(origin_context.get(),
                                         "etc/certs/default/srv-key.pem", SSL_FILETYPE_PEM), 1);
    SSL_CTX_set_alpn_select_cb(origin_context.get(), select_h3_for_origin, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    auto const origin_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(origin_fd, 0);
    ASSERT_TRUE(nonblocking(origin_fd));
    sockaddr_in origin_address {};
    origin_address.sin_family = AF_INET;
    origin_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(origin_fd, reinterpret_cast<sockaddr*>(&origin_address),
                   sizeof(origin_address)), 0);
    socklen_t origin_size = sizeof(origin_address);
    ASSERT_EQ(getsockname(origin_fd, reinterpret_cast<sockaddr*>(&origin_address),
                          &origin_size), 0);
    auto origin_listener = quic::openssl_listener::create(origin_context.get(), origin_fd, true);
    ASSERT_NE(origin_listener, nullptr);

    quic::lifecycle_options lifecycle;
    lifecycle.idle_timeout = std::chrono::milliseconds(300);
    lifecycle.drain_timeout = std::chrono::milliseconds(100);
    auto probe = check_sampling ? std::make_shared<bridge_sampling_probe>() : nullptr;
    quic::listener_service proxy(0, "etc/certs/default/srv-cert.pem",
                                 "etc/certs/default/srv-key.pem", false,
                                 ntohs(origin_address.sin_port), false, lifecycle,
                                 {}, "127.0.0.1",
                                 [probe](auto left, auto right, auto limits, auto) {
                                     return std::make_unique<classified_test_bridge>(
                                         std::move(left), std::move(right), limits, probe);
                                 });
    std::shared_ptr<quic::worker_dispatcher> receiver;
    std::unique_ptr<quic::listener_service> sibling;
    if (use_workers) {
        receiver = std::make_shared<quic::worker_dispatcher>(2);
        quic::datagram_endpoint target;
        auto* address = reinterpret_cast<sockaddr_in*>(&target.address);
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        target.size = sizeof(*address);
        auto const owner = receiver->owner(target);
        proxy.assign_worker(receiver, owner);
        sibling = std::make_unique<quic::listener_service>(0,
            "etc/certs/default/srv-cert.pem", "etc/certs/default/srv-key.pem",
            false, ntohs(origin_address.sin_port), false, lifecycle, quic::resource_limits{},
            "127.0.0.1");
        sibling->assign_worker(receiver, 1 - owner);
    }
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    if (sibling) {
        ASSERT_TRUE(sibling->prepare()) << sibling->last_error();
        ASSERT_EQ(sibling->bound_port(), proxy.bound_port());
    }
    std::thread sibling_thread;
    if (sibling) sibling_thread = std::thread([&] { sibling->run(); });
    std::thread proxy_thread([&proxy]() { proxy.run(); });
    struct thread_guard {
        quic::listener_service& service;
        std::thread& thread;
        quic::listener_service* sibling;
        std::thread& sibling_thread;
        ~thread_guard() {
            service.stop();
            if (sibling) sibling->stop();
            if (thread.joinable()) thread.join();
            if (sibling_thread.joinable()) sibling_thread.join();
        }
    } guard { proxy, proxy_thread, sibling.get(), sibling_thread };

    sockaddr_in proxy_address {};
    proxy_address.sin_family = AF_INET;
    proxy_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    proxy_address.sin_port = htons(proxy.bound_port());
    std::string error;
    auto external = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr*>(&proxy_address),
        sizeof(proxy_address), "Smithproxy-Server-Certificate", &error);
    ASSERT_NE(external, nullptr) << error;

    std::unique_ptr<quic::openssl_connection> origin;
    auto const handshake_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < handshake_deadline
           && (!external->handshake_complete() || !origin || !origin->handshake_complete())) {
        external->drain_events();
        origin_listener->handle_events();
        if (!origin) origin = origin_listener->accept();
        if (origin) origin->drain_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(external->handshake_complete()) << quic::openssl_error_stack();
    ASSERT_NE(origin, nullptr);
    ASSERT_TRUE(origin->handshake_complete()) << quic::openssl_error_stack();
    EXPECT_EQ(external->negotiated_alpn(), "h3");
    EXPECT_EQ(origin->negotiated_alpn(), "h3");

    auto const flow = external->open_flow(sx::multiflow::direction::bidirectional);
    ASSERT_NE(flow.generation, 0U);
    auto external_shared = std::shared_ptr<quic::openssl_connection>(external.get(), [](auto*) {});
    sx::multiflow::MFFlowCom external_stream(external_shared, flow);
    static constexpr char message[] = "through-mfproxy";
    ASSERT_EQ(external_stream.write(external_stream.token(), message, sizeof(message) - 1, 0),
              static_cast<ssize_t>(sizeof(message) - 1));

    std::string received;
    sx::multiflow::flow_handle origin_flow;
    auto const stream_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < stream_deadline && received.empty()) {
        external->drain_events();
        ASSERT_TRUE(origin_listener->handle_events()) << origin_listener->last_error();
        for (auto const& event : origin->drain_events()) {
            if (event.type != sx::multiflow::event_type::flow_open || !event.flow) continue;
            origin_flow = *event.flow;
        }
        if (origin_flow.generation != 0) {
            char buffer[64] {};
            auto const result = origin->read(origin_flow, buffer, sizeof(buffer));
            if (result.size > 0) received.assign(buffer, result.size);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_EQ(received, message);

    auto const diagnostics_deadline = std::chrono::steady_clock::now()
        + std::chrono::seconds(1);
    std::vector<quic::session_snapshot> snapshots;
    while (std::chrono::steady_clock::now() < diagnostics_deadline) {
        snapshots = proxy.session_diagnostics();
        if (!snapshots.empty() && snapshots.front().streams == 1) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    ASSERT_EQ(snapshots.size(), 1U);
    EXPECT_EQ(snapshots.front().state, "active");
    EXPECT_EQ(snapshots.front().server_name, "Smithproxy-Server-Certificate");
    EXPECT_EQ(snapshots.front().downstream_alpn, "h3");
    EXPECT_EQ(snapshots.front().upstream_alpn, "h3");
    for(const auto* tls : {&snapshots.front().downstream_tls, &snapshots.front().upstream_tls}) {
        EXPECT_TRUE(tls->available);
        EXPECT_TRUE(tls->established);
        EXPECT_FALSE(tls->ended);
        EXPECT_STREQ(tls->handshake_status(), "completed");
        EXPECT_EQ(tls->version, "TLSv1.3");
        EXPECT_EQ(tls->server_name, "Smithproxy-Server-Certificate");
        EXPECT_FALSE(tls->cipher.empty());
        EXPECT_FALSE(tls->state.empty());
        EXPECT_FALSE(tls->verify_peer); // This test explicitly disables peer verification.
    }
    EXPECT_EQ(snapshots.front().sift_classifications,
              (std::vector<std::string>{"app.test", "protocol.http3"}));
    EXPECT_EQ(snapshots.front().stream_summary.policies, (std::vector<int>{2, 3}));
    EXPECT_EQ(snapshots.front().stream_summary.filters, (std::vector<std::string>{"test-filter"}));
    EXPECT_EQ(snapshots.front().stream_summary.lored_classifications,
              (std::vector<std::string>{"test-service"}));
    EXPECT_TRUE(snapshots.front().stream_summary.traffic_available);
    EXPECT_EQ(snapshots.front().stream_summary.upload_bps, 1024U);
    EXPECT_EQ(snapshots.front().stream_summary.download_bps, 2048U);
    auto details = proxy.request_session_details([owner = proxy_thread.get_id()](MitmProxy*) {
        return std::optional<std::string>(std::this_thread::get_id() == owner
            ? "rendered on owner" : "wrong thread");
    });
    ASSERT_EQ(details.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_EQ(details.get().at(snapshots.front().id),
              (std::vector<std::string>{"rendered on owner"}));

    EXPECT_EQ(snapshots.front().streams, 1U);
    EXPECT_GT(snapshots.front().forwarded_bytes, 0U);
    EXPECT_NE(snapshots.front().target, "-");

    if (probe) {
        auto const pumps = probe->pumps.load();
        auto const summaries = probe->summaries.load();
        auto const started = std::chrono::steady_clock::now();
        probe->busy = true;
        while (std::chrono::steady_clock::now() - started < std::chrono::milliseconds(250)) {
            external->drain_events();
            ASSERT_TRUE(origin_listener->handle_events());
            origin->drain_events();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        auto const elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        auto const samples = probe->summaries.load() - summaries;
        EXPECT_GE(probe->pumps.load() - pumps, 20U);
        EXPECT_GT(samples, 0U); // Diagnostics still refresh while traffic is busy.
        EXPECT_LE(samples, static_cast<std::size_t>(elapsed / 100 + 2));
        probe->busy = false;
    }

    auto const close_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    bool saw_draining = false;
    while (std::chrono::steady_clock::now() < close_deadline
           && proxy.connection_count() != 0) {
        for(const auto& snapshot : proxy.session_diagnostics()) {
            if(snapshot.state != "draining") continue;
            saw_draining = true;
            EXPECT_EQ(snapshot.sift_classifications, snapshots.front().sift_classifications);
            EXPECT_EQ(snapshot.stream_summary.policies, snapshots.front().stream_summary.policies);
            EXPECT_EQ(snapshot.stream_summary.lored_classifications,
                      snapshots.front().stream_summary.lored_classifications);
            EXPECT_TRUE(snapshot.stream_summary.traffic_available);
            EXPECT_EQ(snapshot.stream_summary.upload_bps, 0U);
            EXPECT_EQ(snapshot.stream_summary.download_bps, 0U);
            EXPECT_TRUE(snapshot.downstream_tls.ended);
            EXPECT_TRUE(snapshot.upstream_tls.ended);
            EXPECT_STREQ(snapshot.downstream_tls.handshake_status(), "completed");
            EXPECT_TRUE(snapshot.downstream_tls.established);
            EXPECT_TRUE(snapshot.upstream_tls.established);
            EXPECT_EQ(snapshot.downstream_tls.cipher, snapshots.front().downstream_tls.cipher);
            EXPECT_EQ(snapshot.upstream_tls.cipher, snapshots.front().upstream_tls.cipher);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_TRUE(saw_draining);
    EXPECT_EQ(proxy.connection_count(), 0U);
    auto const diagnostics = proxy.diagnostics();
    EXPECT_EQ(diagnostics.accepted_sessions, 1U);
    EXPECT_EQ(diagnostics.completed_sessions, 1U);
    EXPECT_EQ(diagnostics.idle_timeouts, 1U);
    if (sibling) {
        EXPECT_EQ(sibling->diagnostics().accepted_sessions, 0U);
        EXPECT_EQ(sibling->dropped_datagrams(), 0U);
        EXPECT_EQ(proxy.dropped_datagrams(), 0U);
    }

    external->close();
    proxy.stop();
    proxy_thread.join();
    origin->close();
    close(origin_fd);
}
TEST_F(QuicListenerService, ProxiesStreamAndCleansUpIdleSession) {
    exercise_proxy_stream(false);
}

TEST_F(QuicListenerService, ReceiverKeepsStreamAndLifecycleOnSelectedWorker) {
    exercise_proxy_stream(true);
}

TEST_F(QuicListenerService, BusyWorkerSamplesDiagnosticsAndPublishesLifecycle) {
    exercise_proxy_stream(false, true);
}

namespace {

class HookSessionSetup final : public sx::proxymaker::SessionSetup {
public:
    sx::proxy::QuicObserver observer {"quic-test", false, true};
    sx::proxy::QuicObserver* quic_observer() override { return &observer; }
    bool start(const std::string&, const std::string&) override { return true; }
};

class QuicHookTest : public QuicListenerService {
protected:
    HookSessionSetup setup;
    quic::Hooks::Callback previous = nullptr;
    inline static unsigned int starts = 0;
    inline static unsigned int failures = 0;
    inline static bool deny = false;
    inline static bool invalid_cipher = false;

    static bool observe(sx::proxymaker::SessionSetup&, quic::HookEvent& event) noexcept {
        if(event.kind == quic::HookEvent::Kind::start) {
            ++starts;
            if(invalid_cipher) event.ciphers = "not-a-cipher";
            return !deny;
        }
        if(event.kind == quic::HookEvent::Kind::failed) ++failures;
        return true;
    }

    void SetUp() override {
        previous = quic::Hooks::registry().handshake;
        quic::Hooks::registry().handshake = &observe;
        starts = failures = 0;
        deny = invalid_cipher = false;
    }

    void TearDown() override {
        quic::Hooks::registry().handshake = previous;
    }
};

TEST_F(QuicHookTest, VetoPrecedesSocketCreation) {
    deny = true;
    std::string error;

    auto connection = quic::connect_with_hooks(nullptr, nullptr, 0, "test", &error, &setup);

    EXPECT_EQ(connection, nullptr);
    EXPECT_EQ(starts, 1U);
    EXPECT_EQ(error, "QUIC start rejected by callback");
}

TEST_F(QuicHookTest, ProbeDoesNotDispatchAndInvalidCipherFailsClosed) {
    auto context = quic::make_openssl_quic_context(false);
    ASSERT_NE(context, nullptr);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(9);
    std::string error;

    // No session context is passed to a certificate probe.
    auto probe = quic::connect_with_hooks(
        context.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address),
        "test", &error, nullptr);
    EXPECT_EQ(starts, 0U);
    probe.reset();

    invalid_cipher = true;
    auto connection = quic::connect_with_hooks(
        context.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address),
        "test", &error, &setup);

    EXPECT_EQ(connection, nullptr);
    EXPECT_EQ(starts, 1U);
    EXPECT_EQ(failures, 1U);
}

} // namespace

#endif

TEST(QuicTlsSnapshot, DistinguishesAbsentPendingCompletedAndEndedHandshakes) {
    quic::tls_snapshot tls;
    EXPECT_STREQ(tls.handshake_status(), "not started");
    tls.ended = true;
    EXPECT_STREQ(tls.handshake_status(), "not started");
    tls.available = true;
    EXPECT_STREQ(tls.handshake_status(), "ended before completion");
    tls.ended = false;
    EXPECT_STREQ(tls.handshake_status(), "pending");
    tls.established = true;
    EXPECT_STREQ(tls.handshake_status(), "completed");
    tls.ended = true;
    EXPECT_STREQ(tls.handshake_status(), "completed");
}

#if SMITHPROXY_OPENSSL_QUIC
namespace {
quic::datagram_endpoint worker_test_address(const char* host, std::uint16_t port = 443) {
    quic::datagram_endpoint result;
    auto* address = reinterpret_cast<sockaddr_in*>(&result.address);
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    inet_pton(AF_INET, host, &address->sin_addr);
    result.size = sizeof(*address);
    return result;
}

quic::datagram_endpoint worker_test_address6(const char* host, std::uint16_t port = 443) {
    quic::datagram_endpoint result;
    auto* address = reinterpret_cast<sockaddr_in6*>(&result.address);
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(port);
    inet_pton(AF_INET6, host, &address->sin6_addr);
    result.size = sizeof(*address);
    return result;
}

bool inbox_readable(quic::worker_dispatcher const& receiver, std::size_t worker) {
    pollfd descriptor {receiver.wake_fd(worker), POLLIN, 0};
    return ::poll(&descriptor, 1, 0) == 1 && (descriptor.revents & POLLIN);
}
}

// Receive two batches through the same storage. Alternating local addresses
// expose stale ancillary metadata; the final probe must return without waiting.
TEST(QuicDatagramBatch, PreservesPayloadAndDestinationAcrossReusedSlots) {
    int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(fd, 0);
    struct socket_guard { int fd; ~socket_guard() { ::close(fd); } } guard {fd};
    int enabled = 1;
    ASSERT_EQ(::setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &enabled, sizeof(enabled)), 0);
    sockaddr_in bound {};
    bound.sin_family = AF_INET;
    ASSERT_EQ(::bind(fd, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)), 0);
    socklen_t length = sizeof(bound);
    ASSERT_EQ(::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &length), 0);
    quic::datagram_receiver receiver;
    for (unsigned round = 0; round < 2; ++round) {
        for (unsigned i = 0; i < quic::datagram_receiver::capacity; ++i) {
            auto target = worker_test_address((i + round) % 2 ? "127.0.0.1" : "127.0.0.2",
                                               ntohs(bound.sin_port));
            std::vector<unsigned char> payload(100 + i, static_cast<unsigned char>(i + round));
            ASSERT_EQ(::sendto(fd, payload.data(), payload.size(), 0,
                reinterpret_cast<sockaddr*>(&target.address), target.size), payload.size());
        }
        unsigned received = 0;
        EXPECT_EQ(receiver.receive(fd, [&](quic::datagram_packet&& packet) {
            auto expected = worker_test_address((received + round) % 2 ? "127.0.0.1" : "127.0.0.2",
                                                 ntohs(bound.sin_port));
            EXPECT_EQ(packet.data, std::vector<unsigned char>(100 + received,
                       static_cast<unsigned char>(received + round)));
            EXPECT_EQ(std::memcmp(&packet.local.address, &expected.address, expected.size), 0);
            EXPECT_TRUE(packet.peer.valid());
            ++received;
        }), quic::datagram_receiver::capacity);
        EXPECT_EQ(received, quic::datagram_receiver::capacity);
    }
    EXPECT_EQ(receiver.receive(fd, [](quic::datagram_packet&&) { ADD_FAILURE(); }), -1);
    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
}

TEST(QuicWorkerDispatcher, BatchPreservesOrderLimitsAndLevelTriggeredWakeups) {
    quic::worker_dispatcher receiver(2);
    std::array<quic::datagram_packet, 6> input;
    for (size_t i = 0; i < input.size(); ++i) {
        input[i].local = worker_test_address(i % 2 ? "198.18.20.1" : "198.18.20.2");
        input[i].data = {static_cast<unsigned char>(i)};
    }
    auto first = receiver.owner(input[0].local);
    auto second = receiver.owner(input[1].local);
    ASSERT_NE(first, second);
    ASSERT_EQ(receiver.enqueue_batch(input.data(), input.size()), input.size());
    std::array<quic::datagram_packet, 2> output;
    EXPECT_EQ(receiver.pop_batch(first, output.data(), 0), 0U);
    ASSERT_TRUE(inbox_readable(receiver, first));
    ASSERT_EQ(receiver.pop_batch(first, output.data(), output.size()), 2U);
    EXPECT_EQ(output[0].data, (std::vector<unsigned char>{0}));
    EXPECT_EQ(output[1].data, (std::vector<unsigned char>{2}));
    EXPECT_TRUE(inbox_readable(receiver, first));
    ASSERT_EQ(receiver.pop_batch(first, output.data(), output.size()), 1U);
    EXPECT_EQ(output[0].data, (std::vector<unsigned char>{4}));
    EXPECT_FALSE(inbox_readable(receiver, first));
    EXPECT_TRUE(inbox_readable(receiver, second));
    receiver.retire(second);
    EXPECT_FALSE(inbox_readable(receiver, second));
    input[0].local = worker_test_address("198.18.20.1");
    EXPECT_EQ(receiver.enqueue_batch(input.data(), 1), 0U);
    EXPECT_EQ(receiver.dropped(second), 1U);

    // A batch may fit only partially. Byte limits still apply per packet.
    for (auto& packet : input) {
        packet.local = worker_test_address("198.18.20.2");
        packet.data.resize(1024 * 1024);
    }
    EXPECT_EQ(receiver.enqueue_batch(input.data(), input.size()), 4U);
    EXPECT_EQ(receiver.dropped(first), 2U);
    EXPECT_TRUE(inbox_readable(receiver, first));
}

TEST(QuicWorkerDispatcher, ConcurrentBatchesDoNotLoseWakeupsOrReorderOwners) {
    quic::worker_dispatcher receiver(4);
    constexpr unsigned batches = 512, width = 16;
    std::atomic_bool done {false};
    std::atomic_size_t accepted {0};
    std::thread producer([&] {
        for (unsigned batch = 0; batch < batches; ++batch) {
            std::array<quic::datagram_packet, width> packets;
            for (unsigned i = 0; i < width; ++i) {
                unsigned sequence = batch * width + i;
                packets[i].local = worker_test_address(("198.18.20." + std::to_string(2 + sequence % 4)).c_str());
                packets[i].data.resize(sizeof(sequence));
                std::memcpy(packets[i].data.data(), &sequence, sizeof(sequence));
            }
            accepted += receiver.enqueue_batch(packets.data(), packets.size());
        }
        done = true;
    });
    std::array<int, 4> previous {-1, -1, -1, -1};
    std::array<pollfd, 4> events;
    for (size_t worker = 0; worker < events.size(); ++worker)
        events[worker] = {receiver.wake_fd(worker), POLLIN, 0};
    size_t consumed = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done && consumed == accepted) break;
        ::poll(events.data(), events.size(), 10);
        for (size_t worker = 0; worker < events.size(); ++worker) {
            if (!(events[worker].revents & POLLIN)) continue;
            std::array<quic::datagram_packet, 7> packets;
            auto count = receiver.pop_batch(worker, packets.data(), packets.size());
            for (size_t i = 0; i < count; ++i) {
                unsigned sequence = 0;
                std::memcpy(&sequence, packets[i].data.data(), sizeof(sequence));
                EXPECT_GT(static_cast<int>(sequence), previous[worker]);
                EXPECT_EQ(receiver.owner(packets[i].local), worker);
                previous[worker] = sequence;
            }
            consumed += count;
        }
    }
    producer.join();
    EXPECT_EQ(consumed, accepted.load());
    size_t drops = 0;
    for (size_t worker = 0; worker < events.size(); ++worker) {
        drops += receiver.dropped(worker);
        EXPECT_FALSE(inbox_readable(receiver, worker));
        EXPECT_GE(previous[worker], 0);
    }
    EXPECT_EQ(consumed + drops, batches * width);
}

TEST(QuicWorkerDispatcher, PreservesOwnerAndMetadataAcrossClientAndPortChanges) {
    quic::worker_dispatcher receiver(4);
    auto first = worker_test_address("198.18.20.1");
    auto second = worker_test_address("198.18.20.2");
    auto const owner = receiver.owner(first);
    ASSERT_NE(owner, receiver.owner(second));
    EXPECT_EQ(owner, receiver.owner(worker_test_address("198.18.20.1", 8443)));
    for (unsigned i = 0; i < 2; ++i) {
        quic::datagram_packet packet;
        packet.local = first;
        packet.peer = worker_test_address(i ? "10.0.0.2" : "10.0.0.1", 1000 + i);
        packet.ingress_ifindex = 7;
        packet.data = {static_cast<unsigned char>(i)};
        ASSERT_TRUE(receiver.enqueue(std::move(packet)));
    }
    EXPECT_TRUE(inbox_readable(receiver, owner));
    EXPECT_FALSE(inbox_readable(receiver, receiver.owner(second)));
    for (unsigned i = 0; i < 2; ++i) {
        quic::datagram_packet packet;
        ASSERT_TRUE(receiver.pop(owner, packet));
        EXPECT_EQ(packet.data, (std::vector<unsigned char>{static_cast<unsigned char>(i)}));
        EXPECT_EQ(packet.ingress_ifindex, 7U);
        EXPECT_EQ(receiver.owner(packet.local), owner);
        EXPECT_EQ(inbox_readable(receiver, owner), i == 0);
    }
    quic::datagram_packet packet;
    EXPECT_FALSE(receiver.pop(owner, packet));
}

TEST(QuicWorkerDispatcher, BoundsQueuesAndNeverStealsFromRetiredOwners) {
    quic::worker_dispatcher receiver(2);
    quic::datagram_packet packet;
    packet.local = worker_test_address("198.18.20.1");
    packet.peer = worker_test_address("10.0.0.1");
    packet.data.resize(65536);
    auto const owner = receiver.owner(packet.local);
    for (int i = 0; i < 64; ++i) ASSERT_TRUE(receiver.enqueue(packet));
    EXPECT_FALSE(receiver.enqueue(packet));
    EXPECT_EQ(receiver.dropped(owner), 1U);
    quic::datagram_packet received;
    ASSERT_TRUE(receiver.pop(owner, received));
    EXPECT_TRUE(receiver.enqueue(packet));
    receiver.retire(owner);
    EXPECT_FALSE(receiver.enqueue(packet));
    EXPECT_FALSE(inbox_readable(receiver, owner));
    EXPECT_FALSE(receiver.pop(1 - owner, received));
    EXPECT_EQ(receiver.dropped(owner), 2U);
}

TEST(QuicWorkerDispatcher, ReceivesOriginalDestinationsIntoDistinctWorkerInboxes) {
    int const fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(fd, 0);
    struct socket_guard { int fd; ~socket_guard() { ::close(fd); } } guard {fd};
    int enabled = 1;
    ASSERT_EQ(::setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &enabled, sizeof(enabled)), 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    ASSERT_EQ(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    socklen_t size = sizeof(address);
    ASSERT_EQ(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size), 0);
    quic::worker_dispatcher receiver(2);
    ASSERT_TRUE(receiver.attach_socket(fd));
    ASSERT_TRUE(receiver.start());
    for (auto host : {"127.0.0.1", "127.0.0.2"}) {
        auto const target = worker_test_address(host, ntohs(address.sin_port));
        unsigned char payload = 73;
        ASSERT_EQ(::sendto(fd, &payload, 1, 0,
            reinterpret_cast<sockaddr const*>(&target.address), target.size), 1);
    }
    pollfd descriptors[] {{receiver.wake_fd(0), POLLIN, 0}, {receiver.wake_fd(1), POLLIN, 0}};
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while ((!inbox_readable(receiver, 0) || !inbox_readable(receiver, 1))
           && std::chrono::steady_clock::now() < deadline) ::poll(descriptors, 2, 10);
    for (std::size_t worker = 0; worker < 2; ++worker) {
        quic::datagram_packet packet;
        ASSERT_TRUE(receiver.pop(worker, packet));
        EXPECT_EQ(receiver.owner(packet.local), worker);
        EXPECT_EQ(packet.data, (std::vector<unsigned char>{73}));
        EXPECT_TRUE(packet.peer.valid());
    }
    receiver.stop();
    EXPECT_EQ(receiver.error(), 0);
}

TEST(QuicWorkerDispatcher, PreservesIpv6DestinationAndIngressInterface) {
    int const fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(fd, 0);
    struct socket_guard { int fd; ~socket_guard() { ::close(fd); } } guard {fd};
    int enabled = 1;
    ASSERT_EQ(::setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &enabled, sizeof(enabled)), 0);
    ASSERT_EQ(::setsockopt(fd, SOL_IPV6, IPV6_RECVPKTINFO, &enabled, sizeof(enabled)), 0);
    sockaddr_in6 address {};
    address.sin6_family = AF_INET6;
    ASSERT_EQ(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    socklen_t size = sizeof(address);
    ASSERT_EQ(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size), 0);

    quic::worker_dispatcher receiver(4);
    EXPECT_NE(receiver.owner(worker_test_address6("fd00::1")),
              receiver.owner(worker_test_address6("fd00::2")));
    EXPECT_EQ(receiver.owner(worker_test_address6("fd00::1", 443)),
              receiver.owner(worker_test_address6("fd00::1", 8443)));
    ASSERT_TRUE(receiver.attach_socket(fd));
    ASSERT_TRUE(receiver.start());
    auto const target = worker_test_address6("::1", ntohs(address.sin6_port));
    auto const owner = receiver.owner(target);
    unsigned char payload = 91;
    ASSERT_EQ(::sendto(fd, &payload, 1, 0,
        reinterpret_cast<sockaddr const*>(&target.address), target.size), 1);
    pollfd descriptor {receiver.wake_fd(owner), POLLIN, 0};
    ASSERT_EQ(::poll(&descriptor, 1, 1000), 1);
    quic::datagram_packet packet;
    ASSERT_TRUE(receiver.pop(owner, packet));
    EXPECT_EQ(packet.local.address.ss_family, AF_INET6);
    EXPECT_EQ(packet.peer.address.ss_family, AF_INET6);
    EXPECT_EQ(reinterpret_cast<sockaddr_in6 const*>(&packet.local.address)->sin6_port,
              address.sin6_port);
    EXPECT_EQ(receiver.owner(packet.local), owner);
    EXPECT_GT(packet.ingress_ifindex, 0U);
    EXPECT_EQ(packet.data, (std::vector<unsigned char>{91}));
    receiver.stop();
    EXPECT_EQ(receiver.error(), 0);
}

TEST(QuicWorkerDispatcher, DoesNotLoseWakeupsWhileProducerAndConsumerOverlap) {
    quic::worker_dispatcher receiver(2);
    auto const destination = worker_test_address("198.18.20.1");
    auto const owner = receiver.owner(destination);
    constexpr unsigned count = 500;
    std::thread producer([&] {
        for (unsigned i = 0; i < count; ++i) {
            quic::datagram_packet packet;
            packet.local = destination;
            packet.peer = worker_test_address("10.0.0.1");
            packet.data = {static_cast<unsigned char>(i)};
            receiver.enqueue(std::move(packet));
            std::this_thread::yield();
        }
    });
    struct thread_guard { std::thread& thread; ~thread_guard() { thread.join(); } } guard {producer};
    for (unsigned i = 0; i < count; ++i) {
        pollfd descriptor {receiver.wake_fd(owner), POLLIN, 0};
        ASSERT_EQ(::poll(&descriptor, 1, 1000), 1);
        quic::datagram_packet packet;
        ASSERT_TRUE(receiver.pop(owner, packet));
        EXPECT_EQ(packet.data, (std::vector<unsigned char>{static_cast<unsigned char>(i)}));
    }
    EXPECT_FALSE(inbox_readable(receiver, owner));
    EXPECT_EQ(receiver.dropped(owner), 0U);
}
#endif
