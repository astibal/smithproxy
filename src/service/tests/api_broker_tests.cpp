#include <service/api/api_broker.hpp>
#include <service/cli/cli_broker.hpp>
#ifdef USE_LMHPP
#include <ext/lmhpp/include/lmhttpd.hpp>
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <thread>

#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

#ifdef USE_LMHPP
class TestController final : public lmh::DynamicController {
public:
    bool validPath(const char* path, const char* method) override {
        return std::string_view(path) == "/test" && std::string_view(method) == "GET";
    }

    lmh::ResponseParams createResponse(MHD_Connection*, const char*, const char*, const char*,
                                       size_t*, void**, std::stringstream& response) override {
        response << "broker-ok";
        return {};
    }
};
#endif

std::uint16_t unused_loopback_port() {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0) return 0;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd); return 0;
    }
    socklen_t size = sizeof(address);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size);
    ::close(fd);
    return ntohs(address.sin_port);
}

int connect_loopback(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        if(::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) return fd;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ::close(fd);
    return -1;
}

void verify_relay(int tcp, int core) {
    ASSERT_EQ(::send(tcp, "request", 7, MSG_NOSIGNAL), 7);
    std::array<char, 16> data{};
    ASSERT_EQ(::read(core, data.data(), data.size()), 7);
    EXPECT_EQ(std::string_view(data.data(), 7), "request");
    ASSERT_EQ(::send(core, "response", 8, MSG_NOSIGNAL), 8);
    ASSERT_EQ(::read(tcp, data.data(), data.size()), 8);
    EXPECT_EQ(std::string_view(data.data(), 8), "response");
}

TEST(ApiBrokerTest, InternalBrokerRelaysRawStreamWithoutPreamble) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker({"127.0.0.1", port, {"*"}, {}}), 0);
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    verify_relay(tcp, core);
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        const auto stats = sx::comm::api::stats();
        if(stats.bytes_to_core == 7 && stats.bytes_from_core == 8) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto stats = sx::comm::api::stats();
    EXPECT_EQ(stats.accepted, 1);
    EXPECT_EQ(stats.rejected, 0);
    EXPECT_EQ(stats.peak_active, 1);
    EXPECT_EQ(stats.bytes_to_core, 7);
    EXPECT_EQ(stats.bytes_from_core, 8);
    ::close(core);
    ::close(listener);
    ::close(tcp);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
}

TEST(ApiBrokerTest, ExternalBrokerUsesFilesystemCommSocket) {
    char directory_template[] = "./smithproxy-api-broker-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    const std::string path = std::string(directory) + "/api.sock";
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::prepare_external_ingress(path), 0);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        sx::comm::stream::BrokerServer server({"127.0.0.1", port, path, {}, {"*"}, {}});
        ::_exit(server.run() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    verify_relay(tcp, core);
    ::close(core);
    ::close(listener);
    ::close(tcp);
    ASSERT_EQ(::kill(child, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(::rmdir(directory), 0);
}

TEST(ApiBrokerTest, BrokerRejectsClientOutsideAllowlist) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker(
        {"127.0.0.1", port, {"192.0.2.1"}, {}}), 0);
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    pollfd descriptor{listener, POLLIN, 0};
    EXPECT_EQ(::poll(&descriptor, 1, 200), 0);
    const auto stats = sx::comm::api::stats();
    EXPECT_EQ(stats.accepted, 1);
    EXPECT_EQ(stats.rejected, 1);
    ::close(listener);
    ::close(tcp);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
}

TEST(ApiBrokerTest, InternalBrokerFailureInvokesFatalHandler) {
    std::atomic<bool> failed{false};
    sx::comm::api::set_internal_failure_handler([&failed] { failed.store(true); });
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker({"127.0.0.1", port, {"*"}, {}}), 0);
    ASSERT_EQ(::kill(sx::comm::api::internal_broker_pid(), SIGKILL), 0);
    for(unsigned attempt = 0; attempt < 100 && !failed.load(); ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_TRUE(failed.load());
    EXPECT_EQ(sx::comm::api::stop_broker(), -1);
    sx::comm::api::set_internal_failure_handler({});
}

#ifdef USE_LMHPP
TEST(ApiBrokerTest, MicroHttpdServesRequestsThroughBrokerAndUnixListener) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker({"127.0.0.1", port, {"*"}, {}}), 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    std::atomic<bool> terminate{false};
    lmh::WebServer server(0);
    server.options().listen_socket = listener;
    server.options().handler_should_terminate = [&terminate] { return terminate.load(); };
    server.addController(std::make_shared<TestController>());
    std::thread server_thread([&server] { server.start(); });

    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    constexpr std::string_view request =
        "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    ASSERT_EQ(::send(tcp, request.data(), request.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(request.size()));
    std::string response;
    std::array<char, 1024> buffer{};
    for(;;) {
        const auto count = ::read(tcp, buffer.data(), buffer.size());
        if(count <= 0) break;
        response.append(buffer.data(), static_cast<std::size_t>(count));
    }
    EXPECT_NE(response.find("200 OK"), std::string::npos);
    EXPECT_NE(response.find("broker-ok"), std::string::npos);

    ::close(tcp);
    terminate.store(true);
    server_thread.join();
    ::close(listener);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
}
#endif

} // namespace
