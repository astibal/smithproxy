#include <service/cli/cli_broker.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <thread>

#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

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

TEST(CliBrokerTest, InternalBrokerRelaysBothDirections) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::cli::start_internal_broker(port), 0);
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::cli::ingress_fd();
    ASSERT_GE(listener, 0);
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    ASSERT_TRUE(sx::comm::cli::receive_handshake(core));

    ASSERT_EQ(::send(tcp, "client", 6, MSG_NOSIGNAL), 6);
    std::array<char, 16> data{};
    ASSERT_EQ(::read(core, data.data(), data.size()), 6);
    EXPECT_EQ(std::string_view(data.data(), 6), "client");
    ASSERT_EQ(::send(core, "server", 6, MSG_NOSIGNAL), 6);
    ASSERT_EQ(::read(tcp, data.data(), data.size()), 6);
    EXPECT_EQ(std::string_view(data.data(), 6), "server");

    ::close(core);
    ::close(listener);
    ::close(tcp);
    EXPECT_EQ(sx::comm::cli::stop_broker(), 0);
}

TEST(CliBrokerTest, InternalBrokerFailureInvokesFatalHandler) {
    std::atomic<bool> failed{false};
    sx::comm::cli::set_internal_failure_handler([&failed] { failed.store(true); });
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::cli::start_internal_broker(port), 0);
    ASSERT_EQ(::kill(sx::comm::cli::internal_broker_pid(), SIGKILL), 0);
    for(unsigned attempt = 0; attempt < 100 && !failed.load(); ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_TRUE(failed.load());
    EXPECT_EQ(sx::comm::cli::stop_broker(), -1);
    sx::comm::cli::set_internal_failure_handler({});
}

TEST(CliBrokerTest, ExternalBrokerUsesFilesystemCommSocket) {
    char directory_template[] = "./smithproxy-cli-broker-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    const std::string path = std::string(directory) + "/cli.sock";
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::cli::prepare_external_ingress(path), 0);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        sx::comm::cli::CliBrokerServer server({"127.0.0.1", port, path});
        ::_exit(server.run() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::cli::ingress_fd();
    ASSERT_GE(listener, 0);
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    EXPECT_TRUE(sx::comm::cli::receive_handshake(core));
    ASSERT_EQ(::send(tcp, "external", 8, MSG_NOSIGNAL), 8);
    std::array<char, 16> data{};
    ASSERT_EQ(::read(core, data.data(), data.size()), 8);
    EXPECT_EQ(std::string_view(data.data(), 8), "external");

    ::close(core);
    ::close(listener);
    ::close(tcp);
    ASSERT_EQ(::kill(child, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(sx::comm::cli::stop_broker(), 0);
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(::rmdir(directory), 0);
}

} // namespace
