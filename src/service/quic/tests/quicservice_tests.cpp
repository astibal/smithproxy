#include <gtest/gtest.h>

#include "service/quic/quicservice.hpp"

#include "proxy/multiflow/mfflowcom.hpp"

#include <chrono>
#include <thread>

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace quic = sx::quic;

TEST(QuicListenerService, PreparesAndStopsLoopbackListener) {
    quic::listener_service service(0,
                                   "etc/certs/default/srv-cert.pem",
                                   "etc/certs/default/srv-key.pem",
                                   false);

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
}

#if SMITHPROXY_OPENSSL_QUIC
namespace {

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

TEST(QuicListenerService, ProxiesStreamToSniOrigin) {
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

    quic::listener_service proxy(0, "etc/certs/default/srv-cert.pem",
                                 "etc/certs/default/srv-key.pem", false,
                                 ntohs(origin_address.sin_port));
    ASSERT_TRUE(proxy.prepare()) << proxy.last_error();
    std::thread proxy_thread([&proxy]() { proxy.run(); });
    struct thread_guard {
        quic::listener_service& service;
        std::thread& thread;
        ~thread_guard() {
            service.stop();
            if (thread.joinable()) thread.join();
        }
    } guard { proxy, proxy_thread };

    sockaddr_in proxy_address {};
    proxy_address.sin_family = AF_INET;
    proxy_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    proxy_address.sin_port = htons(proxy.bound_port());
    std::string error;
    auto external = quic::connect_openssl_quic(
        client_context.get(), reinterpret_cast<sockaddr*>(&proxy_address),
        sizeof(proxy_address), "127.0.0.1", &error);
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

    proxy.stop();
    proxy_thread.join();
    external->close();
    origin->close();
    close(origin_fd);
}
#endif
