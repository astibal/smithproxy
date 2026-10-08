#include <service/webhook/webhook_broker.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace {

struct TcpListener {
    int fd = -1;
    std::uint16_t port = 0;
};

TcpListener make_tcp_listener() {
    TcpListener result;
    result.fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(result.fd < 0) return result;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if(::bind(result.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0
       || ::listen(result.fd, 16) != 0) {
        ::close(result.fd); result.fd = -1; return result;
    }
    socklen_t size = sizeof(address);
    if(::getsockname(result.fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
        ::close(result.fd); result.fd = -1; return result;
    }
    result.port = ntohs(address.sin_port);
    return result;
}

bool wait_for_path(const std::string& path, bool expected = true) {
    for(unsigned attempt = 0; attempt < 200; ++attempt) {
        if(std::filesystem::exists(path) == expected) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

int connect_unix(const std::string& path) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if(path.size() >= sizeof(address.sun_path)) { ::close(fd); errno = ENAMETOOLONG; return -1; }
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    if(::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        const int saved = errno; ::close(fd); errno = saved; return -1;
    }
    return fd;
}

bool write_all(int fd, const std::string& data) {
    std::size_t offset = 0;
    while(offset < data.size()) {
        const auto count = ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if(count > 0) { offset += static_cast<std::size_t>(count); continue; }
        if(count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool read_exact(int fd, std::string& output, std::size_t size) {
    output.assign(size, '\0');
    std::size_t offset = 0;
    while(offset < size) {
        const auto count = ::read(fd, output.data() + offset, size - offset);
        if(count > 0) { offset += static_cast<std::size_t>(count); continue; }
        if(count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

std::size_t append_response(char* data, std::size_t size, std::size_t count, void* context) {
    const auto bytes = size * count;
    static_cast<std::string*>(context)->append(data, bytes);
    return bytes;
}

std::string source_path(const char* relative) {
    return std::string(SMITHPROXY_SOURCE_DIR) + "/" + relative;
}

CURLcode allow_expired_test_fixture(CURL*, void* ssl_context, void*) {
    auto* parameters = ::SSL_CTX_get0_param(static_cast<SSL_CTX*>(ssl_context));
    return parameters && ::X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_NO_CHECK_TIME) == 1
        ? CURLE_OK : CURLE_SSL_CERTPROBLEM;
}

class WebhookBrokerTest : public ::testing::Test {
protected:
    void SetUp() override {
        char pattern[] = "./smithproxy-webhook-broker-test-XXXXXX";
        char* directory = ::mkdtemp(pattern);
        ASSERT_NE(directory, nullptr);
        directory_ = directory;
        path_ = directory_ + "/webhook.sock";
    }

    void TearDown() override {
        sx::comm::webhook::clear_transport();
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    std::string directory_;
    std::string path_;
};

TEST_F(WebhookBrokerTest, SpecializationStoresOnlyTheUnixTransportPath) {
    EXPECT_FALSE(sx::comm::webhook::enabled());
    ASSERT_EQ(sx::comm::webhook::configure_transport(path_), 0);
    EXPECT_TRUE(sx::comm::webhook::enabled());
    EXPECT_EQ(sx::comm::webhook::transport_path(), path_);
    sx::comm::webhook::clear_transport();
    EXPECT_FALSE(sx::comm::webhook::enabled());
}

TEST_F(WebhookBrokerTest, RelaysOpaqueBinaryStreamAndPreservesHalfClose) {
    auto upstream_listener = make_tcp_listener();
    ASSERT_GE(upstream_listener.fd, 0);
    auto* stats = sx::comm::stream::create_tcp_relay_shared_stats();
    ASSERT_NE(stats, nullptr);
    std::atomic<bool> stop{false};
    int server_result = -1;
    sx::comm::webhook::BrokerServer server(
        {path_, "127.0.0.1", upstream_listener.port, {}, 16, 1000}, stats);
    std::thread broker([&] { server_result = server.run_until(stop); });
    ASSERT_TRUE(wait_for_path(path_));
    EXPECT_EQ(std::filesystem::status(path_).permissions()
                  & (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
              std::filesystem::perms::none);
    const int client = connect_unix(path_);
    ASSERT_GE(client, 0);
    const int upstream = ::accept4(upstream_listener.fd, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(upstream, 0);

    std::string payload(256U * 1024U, '\0');
    for(std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>((i * 193U + 11U) & 0xffU);
    bool sent = false;
    std::thread sender([&] { sent = write_all(client, payload); });
    std::string received;
    EXPECT_TRUE(read_exact(upstream, received, payload.size()));
    sender.join();
    EXPECT_TRUE(sent);
    EXPECT_EQ(received, payload);
    ASSERT_EQ(::shutdown(client, SHUT_WR), 0);
    std::array<char, 1> byte{};
    EXPECT_EQ(::read(upstream, byte.data(), byte.size()), 0);
    ASSERT_TRUE(write_all(upstream, "response-after-half-close"));
    ASSERT_EQ(::shutdown(upstream, SHUT_WR), 0);
    EXPECT_TRUE(read_exact(client, received, 25));
    EXPECT_EQ(received, "response-after-half-close");

    ::close(upstream);
    ::close(client);
    ::close(upstream_listener.fd);
    stop.store(true);
    broker.join();
    EXPECT_EQ(server_result, 0);
    const auto snapshot = sx::comm::stream::tcp_relay_snapshot(stats);
    EXPECT_EQ(snapshot.accepted, 1U);
    EXPECT_EQ(snapshot.upstream_connect_errors, 0U);
    EXPECT_EQ(snapshot.bytes_to_upstream, payload.size());
    EXPECT_EQ(snapshot.bytes_from_upstream, 25U);
    sx::comm::stream::destroy_tcp_relay_shared_stats(stats);
    EXPECT_FALSE(std::filesystem::exists(path_));
}

TEST_F(WebhookBrokerTest, FailedFixedDestinationClosesOnlyTheSession) {
    auto unavailable = make_tcp_listener();
    ASSERT_GE(unavailable.fd, 0);
    const auto port = unavailable.port;
    ::close(unavailable.fd);
    auto* stats = sx::comm::stream::create_tcp_relay_shared_stats();
    ASSERT_NE(stats, nullptr);
    std::atomic<bool> stop{false};
    int server_result = -1;
    sx::comm::webhook::BrokerServer server(
        {path_, "127.0.0.1", port, {}, 16, 250}, stats);
    std::thread broker([&] { server_result = server.run_until(stop); });
    ASSERT_TRUE(wait_for_path(path_));
    for(unsigned attempt = 0; attempt < 2; ++attempt) {
        const int client = connect_unix(path_);
        ASSERT_GE(client, 0);
        pollfd descriptor{client, POLLHUP, 0};
        EXPECT_GT(::poll(&descriptor, 1, 1000), 0);
        ::close(client);
    }
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        if(sx::comm::stream::tcp_relay_snapshot(stats).completed == 2) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto snapshot = sx::comm::stream::tcp_relay_snapshot(stats);
    EXPECT_EQ(snapshot.accepted, 2U);
    EXPECT_EQ(snapshot.upstream_connect_errors, 2U);
    EXPECT_EQ(snapshot.completed, 2U);
    stop.store(true);
    broker.join();
    EXPECT_EQ(server_result, 0);
    sx::comm::stream::destroy_tcp_relay_shared_stats(stats);
}

TEST_F(WebhookBrokerTest, CurlKeepsUrlIdentityWhileUsingUnixTransport) {
    auto upstream_listener = make_tcp_listener();
    ASSERT_GE(upstream_listener.fd, 0);
    std::atomic<bool> stop{false};
    int server_result = -1;
    sx::comm::webhook::BrokerServer server(
        {path_, "127.0.0.1", upstream_listener.port, {}, 16, 1000});
    std::thread broker([&] { server_result = server.run_until(stop); });
    ASSERT_TRUE(wait_for_path(path_));

    std::string request;
    std::thread endpoint([&] {
        const int connection = ::accept4(upstream_listener.fd, nullptr, nullptr, SOCK_CLOEXEC);
        if(connection < 0) return;
        std::array<char, 4096> buffer{};
        while(request.find("\r\n\r\nrelay-test") == std::string::npos) {
            const auto count = ::read(connection, buffer.data(), buffer.size());
            if(count <= 0) break;
            request.append(buffer.data(), static_cast<std::size_t>(count));
        }
        const std::string response =
            "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nbroker-ok";
        (void)write_all(connection, response);
        ::close(connection);
    });

    CURL* curl = ::curl_easy_init();
    ASSERT_NE(curl, nullptr);
    std::string response;
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_URL,
                                 "http://webhook.identity.invalid/hook?source=smithproxy"), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, path_.c_str()), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_PROXY, ""), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "relay-test"), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 10L), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response), CURLE_OK);
    EXPECT_EQ(::curl_easy_perform(curl), CURLE_OK);
    ::curl_easy_cleanup(curl);
    endpoint.join();

    EXPECT_NE(request.find("POST /hook?source=smithproxy HTTP/1.1\r\n"), std::string::npos);
    EXPECT_NE(request.find("Host: webhook.identity.invalid\r\n"), std::string::npos);
    EXPECT_NE(request.find("\r\n\r\nrelay-test"), std::string::npos);
    EXPECT_EQ(response, "broker-ok");

    ::close(upstream_listener.fd);
    stop.store(true);
    broker.join();
    EXPECT_EQ(server_result, 0);
}

TEST_F(WebhookBrokerTest, MissingUnixTransportNeverFallsBackToReachableTcpTarget) {
    auto direct_listener = make_tcp_listener();
    ASSERT_GE(direct_listener.fd, 0);

    CURL* curl = ::curl_easy_init();
    ASSERT_NE(curl, nullptr);
    const auto url = "http://127.0.0.1:" + std::to_string(direct_listener.port) + "/must-not-arrive";
    const auto missing = directory_ + "/missing.sock";
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_URL, url.c_str()), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, missing.c_str()), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_PROXY, ""), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 250L), CURLE_OK);
    EXPECT_EQ(::curl_easy_perform(curl), CURLE_COULDNT_CONNECT);
    ::curl_easy_cleanup(curl);

    pollfd descriptor{direct_listener.fd, POLLIN, 0};
    EXPECT_EQ(::poll(&descriptor, 1, 200), 0);
    ::close(direct_listener.fd);
}

TEST_F(WebhookBrokerTest, HttpsPreservesSniAndCertificateIdentityAcrossRelay) {
    auto upstream_listener = make_tcp_listener();
    ASSERT_GE(upstream_listener.fd, 0);
    std::atomic<bool> stop{false};
    int server_result = -1;
    sx::comm::webhook::BrokerServer server(
        {path_, "127.0.0.1", upstream_listener.port, {}, 16, 1000});
    std::thread broker([&] { server_result = server.run_until(stop); });
    ASSERT_TRUE(wait_for_path(path_));

    SSL_CTX* context = ::SSL_CTX_new(::TLS_server_method());
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(::SSL_CTX_use_certificate_file(
                  context, source_path("etc/certs/default/srv-cert.pem").c_str(), SSL_FILETYPE_PEM), 1);
    ASSERT_EQ(::SSL_CTX_use_PrivateKey_file(
                  context, source_path("etc/certs/default/srv-key.pem").c_str(), SSL_FILETYPE_PEM), 1);
    std::string observed_sni;
    std::string request;
    bool tls_ok = false;
    std::thread endpoint([&] {
        const int connection = ::accept4(upstream_listener.fd, nullptr, nullptr, SOCK_CLOEXEC);
        if(connection < 0) return;
        SSL* ssl = ::SSL_new(context);
        if(!ssl) { ::close(connection); return; }
        ::SSL_set_fd(ssl, connection);
        if(::SSL_accept(ssl) == 1) {
            if(const char* name = ::SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))
                observed_sni = name;
            std::array<char, 4096> buffer{};
            while(request.find("\r\n\r\n") == std::string::npos) {
                const int count = ::SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
                if(count <= 0) break;
                request.append(buffer.data(), static_cast<std::size_t>(count));
            }
            const std::string response =
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-ok";
            tls_ok = ::SSL_write(ssl, response.data(), static_cast<int>(response.size()))
                     == static_cast<int>(response.size());
        }
        ::SSL_shutdown(ssl);
        ::SSL_free(ssl);
        ::close(connection);
    });

    CURL* curl = ::curl_easy_init();
    ASSERT_NE(curl, nullptr);
    std::string response;
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_URL,
                                 "https://Smithproxy-Server-Certificate/secure-hook"), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, path_.c_str()), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_PROXY, ""), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_CAINFO,
                                 source_path("etc/certs/default/ca-cert.pem").c_str()), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION,
                                 allow_expired_test_fixture), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response), CURLE_OK);
    ASSERT_EQ(::curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response), CURLE_OK);
    EXPECT_EQ(::curl_easy_perform(curl), CURLE_OK);
    ::curl_easy_cleanup(curl);
    endpoint.join();

    EXPECT_TRUE(tls_ok);
    EXPECT_EQ(observed_sni, "smithproxy-server-certificate");
    EXPECT_NE(request.find("GET /secure-hook HTTP/1.1\r\n"), std::string::npos);
    EXPECT_NE(request.find("Host: Smithproxy-Server-Certificate\r\n"), std::string::npos);
    EXPECT_EQ(response, "tls-ok");

    ::SSL_CTX_free(context);
    ::close(upstream_listener.fd);
    stop.store(true);
    broker.join();
    EXPECT_EQ(server_result, 0);
}

TEST_F(WebhookBrokerTest, IdleSessionIsClosedWithoutStoppingBroker) {
    auto upstream_listener = make_tcp_listener();
    ASSERT_GE(upstream_listener.fd, 0);
    auto* stats = sx::comm::stream::create_tcp_relay_shared_stats();
    ASSERT_NE(stats, nullptr);
    std::atomic<bool> stop{false};
    int server_result = -1;
    sx::comm::webhook::BrokerServer server(
        {path_, "127.0.0.1", upstream_listener.port, {}, 16, 1000, 100}, stats);
    std::thread broker([&] { server_result = server.run_until(stop); });
    ASSERT_TRUE(wait_for_path(path_));
    const int client = connect_unix(path_);
    ASSERT_GE(client, 0);
    const int upstream = ::accept4(upstream_listener.fd, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(upstream, 0);
    pollfd descriptor{client, POLLHUP, 0};
    EXPECT_GT(::poll(&descriptor, 1, 1000), 0);
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        if(sx::comm::stream::tcp_relay_snapshot(stats).completed == 1) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto snapshot = sx::comm::stream::tcp_relay_snapshot(stats);
    EXPECT_EQ(snapshot.completed, 1U);
    EXPECT_EQ(snapshot.relay_errors, 1U);
    EXPECT_EQ(snapshot.active, 0U);
    ::close(upstream);
    ::close(client);
    ::close(upstream_listener.fd);
    stop.store(true);
    broker.join();
    EXPECT_EQ(server_result, 0);
    sx::comm::stream::destroy_tcp_relay_shared_stats(stats);
}

TEST_F(WebhookBrokerTest, SessionLimitRejectsExcessClients) {
    auto upstream_listener = make_tcp_listener();
    ASSERT_GE(upstream_listener.fd, 0);
    auto* stats = sx::comm::stream::create_tcp_relay_shared_stats();
    ASSERT_NE(stats, nullptr);
    std::atomic<bool> stop{false};
    int server_result = -1;
    sx::comm::webhook::BrokerServer server(
        {path_, "127.0.0.1", upstream_listener.port, {}, 1, 1000, 5000}, stats);
    std::thread broker([&] { server_result = server.run_until(stop); });
    ASSERT_TRUE(wait_for_path(path_));
    const int first = connect_unix(path_);
    ASSERT_GE(first, 0);
    const int upstream = ::accept4(upstream_listener.fd, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(upstream, 0);
    const int excess = connect_unix(path_);
    ASSERT_GE(excess, 0);
    pollfd descriptor{excess, POLLHUP, 0};
    EXPECT_GT(::poll(&descriptor, 1, 1000), 0);
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        if(sx::comm::stream::tcp_relay_snapshot(stats).rejected == 1) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto snapshot = sx::comm::stream::tcp_relay_snapshot(stats);
    EXPECT_EQ(snapshot.accepted, 2U);
    EXPECT_EQ(snapshot.rejected, 1U);
    EXPECT_EQ(snapshot.active, 1U);
    ::close(excess);
    ::close(upstream);
    ::close(first);
    ::close(upstream_listener.fd);
    stop.store(true);
    broker.join();
    EXPECT_EQ(server_result, 0);
    sx::comm::stream::destroy_tcp_relay_shared_stats(stats);
}

} // namespace
