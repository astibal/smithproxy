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

bool write_all(int fd, const char* data, std::size_t size) {
    std::size_t offset = 0;
    while(offset < size) {
        const auto count = ::send(fd, data + offset, size - offset, MSG_NOSIGNAL);
        if(count > 0) { offset += static_cast<std::size_t>(count); continue; }
        if(count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool read_exact(int fd, std::string& output, std::size_t size) {
    output.clear();
    output.resize(size);
    std::size_t offset = 0;
    while(offset < size) {
        const auto count = ::read(fd, output.data() + offset, size - offset);
        if(count > 0) { offset += static_cast<std::size_t>(count); continue; }
        if(count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
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
    EXPECT_EQ(std::filesystem::status(path).permissions()
                  & (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
              std::filesystem::perms::none);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        sx::comm::stream::BrokerServer server({"127.0.0.1", port, path, {}, {"*"}, {}, 256});
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

TEST(ApiBrokerTest, IdleClientCannotBlockIndependentSession) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker({"127.0.0.1", port, {"*"}, {}}), 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    const int idle_tcp = connect_loopback(port);
    ASSERT_GE(idle_tcp, 0);
    const int idle_core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(idle_core, 0);
    const int active_tcp = connect_loopback(port);
    ASSERT_GE(active_tcp, 0);
    const int active_core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(active_core, 0);
    ASSERT_EQ(::send(active_tcp, "independent", 11, MSG_NOSIGNAL), 11);
    std::array<char, 16> data{};
    ASSERT_EQ(::read(active_core, data.data(), data.size()), 11);
    EXPECT_EQ(std::string_view(data.data(), 11), "independent");
    ::close(active_core);
    ::close(active_tcp);
    ::close(idle_core);
    ::close(idle_tcp);
    ::close(listener);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
}

TEST(ApiBrokerTest, PreservesBinaryPayloadAcrossRelayBufferBoundaries) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker({"127.0.0.1", port, {"*"}, {}}), 0);
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    std::string payload(1024U * 1024U, '\0');
    for(std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>((i * 131U + 17U) & 0xffU);
    bool sent = false;
    std::thread sender([&] { sent = write_all(tcp, payload.data(), payload.size()); });
    std::string received;
    EXPECT_TRUE(read_exact(core, received, payload.size()));
    sender.join();
    EXPECT_TRUE(sent);
    EXPECT_EQ(received, payload);

    sent = false;
    std::thread reverse_sender([&] { sent = write_all(core, payload.data(), payload.size()); });
    EXPECT_TRUE(read_exact(tcp, received, payload.size()));
    reverse_sender.join();
    EXPECT_TRUE(sent);
    EXPECT_EQ(received, payload);
    ::close(core);
    ::close(listener);
    ::close(tcp);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
}

TEST(ApiBrokerTest, HalfCloseStillAllowsResponseDirectionToDrain) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker({"127.0.0.1", port, {"*"}, {}}), 0);
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    ASSERT_EQ(::send(tcp, "request", 7, MSG_NOSIGNAL), 7);
    ASSERT_EQ(::shutdown(tcp, SHUT_WR), 0);
    std::string received;
    ASSERT_TRUE(read_exact(core, received, 7));
    EXPECT_EQ(received, "request");
    std::array<char, 1> eof{};
    EXPECT_EQ(::read(core, eof.data(), eof.size()), 0);
    ASSERT_EQ(::send(core, "response", 8, MSG_NOSIGNAL), 8);
    ASSERT_EQ(::shutdown(core, SHUT_WR), 0);
    ASSERT_TRUE(read_exact(tcp, received, 8));
    EXPECT_EQ(received, "response");
    EXPECT_EQ(::read(tcp, eof.data(), eof.size()), 0);
    ::close(core);
    ::close(listener);
    ::close(tcp);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
}

TEST(ApiBrokerTest, ReapsCompletedSessionsDuringConnectionChurn) {
    constexpr std::uint64_t session_count = 128;
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::start_internal_broker({"127.0.0.1", port, {"*"}, {}}), 0);
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    for(std::uint64_t i = 0; i < session_count; ++i) {
        const int tcp = connect_loopback(port);
        ASSERT_GE(tcp, 0);
        const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        ASSERT_GE(core, 0);
        ::close(core);
        ::close(tcp);
    }
    for(unsigned attempt = 0; attempt < 200; ++attempt) {
        const auto current = sx::comm::api::stats();
        if(current.completed == session_count && current.active == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto stats = sx::comm::api::stats();
    EXPECT_EQ(stats.accepted, session_count);
    EXPECT_EQ(stats.completed, session_count);
    EXPECT_EQ(stats.active, 0);
    ::close(listener);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
}

TEST(ApiBrokerTest, RejectsConnectionsBeyondConfiguredSessionLimit) {
    char directory_template[] = "./smithproxy-api-limit-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    const std::string path = std::string(directory) + "/api.sock";
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::api::prepare_external_ingress(path), 0);
    auto* counters = sx::comm::stream::create_shared_stats();
    ASSERT_NE(counters, nullptr);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        sx::comm::stream::BrokerServer server(
            {"127.0.0.1", port, path, {}, {"*"}, {}, 4}, counters);
        ::_exit(server.run() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    const int listener = sx::comm::api::ingress_fd();
    ASSERT_GE(listener, 0);
    std::array<int, 4> clients{};
    std::array<int, 4> cores{};
    for(std::size_t i = 0; i < clients.size(); ++i) {
        clients[i] = connect_loopback(port);
        ASSERT_GE(clients[i], 0);
        cores[i] = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        ASSERT_GE(cores[i], 0);
    }
    const int rejected = connect_loopback(port);
    ASSERT_GE(rejected, 0);
    pollfd closed{rejected, POLLIN | POLLHUP, 0};
    ASSERT_GT(::poll(&closed, 1, 1000), 0);
    std::array<char, 1> byte{};
    EXPECT_EQ(::read(rejected, byte.data(), byte.size()), 0);
    pollfd no_core{listener, POLLIN, 0};
    EXPECT_EQ(::poll(&no_core, 1, 100), 0);
    const auto stats = sx::comm::stream::snapshot(counters);
    EXPECT_EQ(stats.accepted, 5);
    EXPECT_EQ(stats.rejected, 1);
    EXPECT_EQ(stats.active, 4);
    EXPECT_EQ(stats.peak_active, 4);
    ::close(rejected);
    for(int fd: cores) ::close(fd);
    for(int fd: clients) ::close(fd);
    ::close(listener);
    ASSERT_EQ(::kill(child, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_TRUE(WIFEXITED(status));
    sx::comm::stream::destroy_shared_stats(counters);
    EXPECT_EQ(sx::comm::api::stop_broker(), 0);
    EXPECT_EQ(::rmdir(directory), 0);
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

    const int malformed = connect_loopback(port);
    ASSERT_GE(malformed, 0);
    std::string hostile_request = "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Fill: ";
    hostile_request.append(128U * 1024U, 'A');
    hostile_request.append("\r\n\r\n");
    (void)write_all(malformed, hostile_request.data(), hostile_request.size());
    ::shutdown(malformed, SHUT_WR);
    pollfd malformed_poll{malformed, POLLIN | POLLHUP, 0};
    EXPECT_GE(::poll(&malformed_poll, 1, 2000), 0);
    ::close(malformed);

    // A hostile request must not poison the listener or a later session.
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
