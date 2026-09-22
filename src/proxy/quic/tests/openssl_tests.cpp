#include <gtest/gtest.h>

#include "proxy/quic/openssl.hpp"

#if SMITHPROXY_OPENSSL_QUIC
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <thread>
#endif

namespace quic = sx::quic;
namespace mf = sx::multiflow;

TEST(OpenSslQuic, CapabilityMatchesBuildVersion) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L && !defined(OPENSSL_NO_QUIC)
    EXPECT_TRUE(quic::openssl_quic_available());
#else
    EXPECT_FALSE(quic::openssl_quic_available());
#endif
}

TEST(OpenSslQuic, CreatesClientAndServerContextsWhenAvailable) {
    auto client = quic::make_openssl_quic_context(false);
    auto server = quic::make_openssl_quic_context(true);

    if (quic::openssl_quic_available()) {
        ASSERT_NE(client, nullptr) << quic::openssl_error_stack();
        ASSERT_NE(server, nullptr) << quic::openssl_error_stack();
#if SMITHPROXY_OPENSSL_QUIC
        EXPECT_EQ(SSL_CTX_get_ssl_method(client.get()), OSSL_QUIC_client_method());
        EXPECT_EQ(SSL_CTX_get_ssl_method(server.get()), OSSL_QUIC_server_method());
#endif
    } else {
        EXPECT_EQ(client, nullptr);
        EXPECT_EQ(server, nullptr);
    }
}

#if SMITHPROXY_OPENSSL_QUIC
namespace {

int select_h3(SSL*, const unsigned char** output, unsigned char* output_size,
              const unsigned char* input, unsigned input_size, void*) {
    static constexpr unsigned char supported[] = { 2, 'h', '3' };
    return SSL_select_next_proto(const_cast<unsigned char**>(output), output_size,
                                 supported, sizeof(supported), input, input_size)
            == OPENSSL_NPN_NEGOTIATED
        ? SSL_TLSEXT_ERR_OK
        : SSL_TLSEXT_ERR_NOACK;
}

bool make_nonblocking(int fd) {
    auto const flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

} // namespace

TEST(OpenSslQuic, CreatesNonBlockingServerListenerObject) {
    auto context = quic::make_openssl_quic_context(true);
    ASSERT_NE(context, nullptr) << quic::openssl_error_stack();

    quic::unique_ssl listener(SSL_new_listener(context.get(), 0));
    ASSERT_NE(listener, nullptr) << quic::openssl_error_stack();
    EXPECT_EQ(SSL_is_listener(listener.get()), 1);
    EXPECT_EQ(SSL_set_blocking_mode(listener.get(), 0), 1);
    EXPECT_EQ(SSL_get_blocking_mode(listener.get()), 0);
}

TEST(OpenSslQuic, LoopbackHandshakeExposesBidirectionalStream) {
    auto server_context = quic::make_openssl_quic_context(true);
    auto client_context = quic::make_openssl_quic_context(false);
    ASSERT_NE(server_context, nullptr) << quic::openssl_error_stack();
    ASSERT_NE(client_context, nullptr) << quic::openssl_error_stack();

    ASSERT_EQ(SSL_CTX_use_certificate_chain_file(server_context.get(),
                                                 "etc/certs/default/srv-cert.pem"), 1)
        << quic::openssl_error_stack();
    ASSERT_EQ(SSL_CTX_use_PrivateKey_file(server_context.get(),
                                         "etc/certs/default/srv-key.pem", SSL_FILETYPE_PEM), 1)
        << quic::openssl_error_stack();
    SSL_CTX_set_alpn_select_cb(server_context.get(), select_h3, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    auto const server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    auto const client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(server_fd, 0);
    ASSERT_GE(client_fd, 0);
    ASSERT_TRUE(make_nonblocking(server_fd));
    ASSERT_TRUE(make_nonblocking(client_fd));

    sockaddr_in server_address {};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_address.sin_port = 0;
    ASSERT_EQ(bind(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                   sizeof(server_address)), 0);
    socklen_t address_size = sizeof(server_address);
    ASSERT_EQ(getsockname(server_fd, reinterpret_cast<sockaddr*>(&server_address),
                          &address_size), 0);
    ASSERT_EQ(connect(client_fd, reinterpret_cast<sockaddr*>(&server_address),
                      sizeof(server_address)), 0);

    auto listener = quic::openssl_listener::create(server_context.get(), server_fd, true);
    ASSERT_NE(listener, nullptr) << quic::openssl_error_stack();
    EXPECT_TRUE(listener->local_address_enabled());

    quic::unique_ssl client(SSL_new(client_context.get()));
    ASSERT_NE(client, nullptr) << quic::openssl_error_stack();
    ASSERT_EQ(SSL_set_fd(client.get(), client_fd), 1);
    ASSERT_EQ(SSL_set_blocking_mode(client.get(), 0), 1);
    ASSERT_EQ(SSL_set_tlsext_host_name(client.get(), "localhost"), 1);
    static constexpr unsigned char alpn[] = { 2, 'h', '3' };
    ASSERT_EQ(SSL_set_alpn_protos(client.get(), alpn, sizeof(alpn)), 0);

    std::unique_ptr<quic::openssl_connection> server;
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline
           && (!SSL_is_init_finished(client.get())
               || !server || !SSL_is_init_finished(server->native_handle()))) {
        SSL_connect(client.get());
        listener->handle_events();
        if (!server) server = listener->accept();
        if (server) SSL_do_handshake(server->native_handle());
        SSL_handle_events(client.get());
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(SSL_is_init_finished(client.get())) << quic::openssl_error_stack();
    ASSERT_NE(server, nullptr) << quic::openssl_error_stack();
    ASSERT_TRUE(SSL_is_init_finished(server->native_handle())) << quic::openssl_error_stack();

    quic::openssl_connection client_connection(std::move(client));
    auto const client_flow = client_connection.open_flow(mf::direction::bidirectional);
    ASSERT_NE(client_flow.generation, 0U) << quic::openssl_error_stack();
    static constexpr char message[] = "smithproxy-quic";

    mf::flow_handle server_flow;
    std::string received;
    bool sent = false;
    auto const stream_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < stream_deadline && received.empty()) {
        if (!sent) {
            auto const write_result = client_connection.write(client_flow, message, sizeof(message) - 1);
            ASSERT_TRUE(write_result.status == mf::io_status::ok
                        || write_result.status == mf::io_status::would_block);
            sent = write_result.size == sizeof(message) - 1;
        }
        client_connection.drain_events();
        for (auto const& event : server->drain_events()) {
            if (event.type == mf::event_type::flow_open && event.flow) server_flow = *event.flow;
        }
        if (server_flow.generation != 0) {
            char buffer[64] {};
            auto const read_result = server->read(server_flow, buffer, sizeof(buffer));
            if (read_result.status == mf::io_status::ok) {
                received.assign(buffer, read_result.size);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_EQ(received, message);

    client_connection.close();
    server->close();
    close(client_fd);
    close(server_fd);
}
#endif
