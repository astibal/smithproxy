#include <service/cli/cli_broker.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <poll.h>
#include <pwd.h>
#include <cerrno>
#include <fcntl.h>
#include <thread>

#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

// Inject persistent terminal poll events without racing close() against a worker.
thread_local short injected_poll_event = 0;
extern "C" int __real_poll(pollfd*, nfds_t, int);
extern "C" int __wrap_poll(pollfd* fds, nfds_t count, int timeout) {
    if(injected_poll_event && count == 2) {
        fds[0].revents = injected_poll_event;
        fds[1].revents = 0;
        return 1;
    }
    return __real_poll(fds, count, timeout);
}

namespace {

class DuplexRelayTest : public ::testing::Test {
protected:
    int left[2]{-1, -1};
    int right[2]{-1, -1};
    std::atomic<bool> stop{false};
    std::atomic<bool> done{false};
    std::thread worker;
    int result = 0;
    int error = 0;

    void SetUp() override {
        ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, left), 0);
        ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, right), 0);
        timeval timeout{2, 0};
        for(int fd: {left[0], right[1]}) {
            ASSERT_EQ(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0);
            ASSERT_EQ(::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)), 0);
        }
    }
    void TearDown() override {
        stop.store(true);
        if(worker.joinable()) worker.join();
        for(int fd: {left[0], left[1], right[0], right[1]})
            if(fd >= 0) ::close(fd);
    }
    void start(short event = 0) {
        worker = std::thread([this, event] {
            injected_poll_event = event;
            result = sx::comm::cli::DuplexRelay{}.run(left[1], right[0], stop);
            error = errno;
            done.store(true);
        });
    }
    bool wait_done() {
        for(unsigned i = 0; i < 100 && !done.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return done.load();
    }
};

TEST_F(DuplexRelayTest, PollErrorTerminatesWithoutReadiness) {
    start(POLLERR);
    ASSERT_TRUE(wait_done());
    EXPECT_EQ(result, -1);
    EXPECT_EQ(error, EIO);
}

TEST_F(DuplexRelayTest, PollInvalidTerminatesWithoutReadiness) {
    start(POLLNVAL);
    ASSERT_TRUE(wait_done());
    EXPECT_EQ(result, -1);
    EXPECT_EQ(error, EBADF);
}

TEST_F(DuplexRelayTest, FullClientHangupDoesNotWaitForCore) {
    ::close(left[0]);
    left[0] = -1;
    start();
    ASSERT_TRUE(wait_done());
    EXPECT_EQ(result, 0);
}

TEST_F(DuplexRelayTest, FullCoreHangupDoesNotWaitForClient) {
    ::close(right[1]);
    right[1] = -1;
    start();
    ASSERT_TRUE(wait_done());
    EXPECT_EQ(result, 0);
}

TEST_F(DuplexRelayTest, HangupDrainsMoreThanOneRelayBuffer) {
    const std::string payload(128 * 1024, 'x');
    ASSERT_EQ(::send(left[0], payload.data(), payload.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(payload.size()));
    ::close(left[0]);
    left[0] = -1;
    start();
    std::string received;
    std::array<char, 8192> buffer{};
    ssize_t count;
    while((count = ::read(right[1], buffer.data(), buffer.size())) > 0)
        received.append(buffer.data(), static_cast<std::size_t>(count));
    EXPECT_EQ(count, 0);
    EXPECT_EQ(received, payload);
    ASSERT_TRUE(wait_done());
    EXPECT_EQ(result, 0);
}

TEST_F(DuplexRelayTest, HungUpSourceDoesNotSpinWhileDestinationIsBlocked) {
    const int flags = ::fcntl(right[0], F_GETFL);
    ASSERT_GE(flags, 0);
    ASSERT_EQ(::fcntl(right[0], F_SETFL, flags | O_NONBLOCK), 0);
    std::string expected;
    const std::string filler(8192, 'f');
    ssize_t count;
    while((count = ::send(right[0], filler.data(), filler.size(), MSG_NOSIGNAL)) > 0)
        expected.append(filler.data(), static_cast<std::size_t>(count));
    ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
    ASSERT_EQ(::send(left[0], "tail", 4, MSG_NOSIGNAL), 4);
    expected += "tail";
    ::close(left[0]);
    left[0] = -1;
    start();
    clockid_t worker_clock;
    ASSERT_EQ(::pthread_getcpuclockid(worker.native_handle(), &worker_clock), 0);
    timespec before{}, after{};
    ASSERT_EQ(::clock_gettime(worker_clock, &before), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_EQ(::clock_gettime(worker_clock, &after), 0);
    const auto cpu_ns = (after.tv_sec - before.tv_sec) * 1000000000LL
                      + after.tv_nsec - before.tv_nsec;
    EXPECT_LT(cpu_ns, 50000000LL);
    std::string received;
    std::array<char, 8192> buffer{};
    while((count = ::read(right[1], buffer.data(), buffer.size())) > 0)
        received.append(buffer.data(), static_cast<std::size_t>(count));
    EXPECT_EQ(count, 0);
    EXPECT_EQ(received, expected);
    ASSERT_TRUE(wait_done());
    EXPECT_EQ(result, 0);
}

TEST_F(DuplexRelayTest, HalfCloseStillAllowsReply) {
    ASSERT_EQ(::send(left[0], "request", 7, MSG_NOSIGNAL), 7);
    ASSERT_EQ(::shutdown(left[0], SHUT_WR), 0);
    start();
    std::array<char, 16> buffer{};
    ASSERT_EQ(::recv(right[1], buffer.data(), 7, MSG_WAITALL), 7);
    EXPECT_EQ(std::string_view(buffer.data(), 7), "request");
    ASSERT_EQ(::read(right[1], buffer.data(), buffer.size()), 0);
    EXPECT_FALSE(done.load());
    ASSERT_EQ(::send(right[1], "reply", 5, MSG_NOSIGNAL), 5);
    ASSERT_EQ(::shutdown(right[1], SHUT_WR), 0);
    ASSERT_EQ(::recv(left[0], buffer.data(), 5, MSG_WAITALL), 5);
    EXPECT_EQ(std::string_view(buffer.data(), 5), "reply");
    EXPECT_EQ(::read(left[0], buffer.data(), buffer.size()), 0);
    ASSERT_TRUE(wait_done());
    EXPECT_EQ(result, 0);
}


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

int connect_unix_socket(const std::string& path) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0) return -1;
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
    const auto size = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1U);
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        if(::connect(fd, reinterpret_cast<sockaddr*>(&address), size) == 0) return fd;
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
    for(unsigned attempt = 0; attempt < 100; ++attempt) {
        const auto current = sx::comm::cli::stats();
        if(current.bytes_to_core == 6 && current.bytes_from_core == 6) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto stats = sx::comm::cli::stats();
    EXPECT_EQ(stats.accepted, 1);
    EXPECT_EQ(stats.peak_active, 1);
    EXPECT_EQ(stats.bytes_to_core, 6);
    EXPECT_EQ(stats.bytes_from_core, 6);

    ::close(core);
    ::close(listener);
    ::close(tcp);
    EXPECT_EQ(sx::comm::cli::stop_broker(), 0);
}

TEST(CliBrokerPeerTest, RootWithValidPidIsAllowed) {
    EXPECT_TRUE(sx::comm::stream::unix_peer_allowed(42, 0, {0, 1000}));
}

TEST(CliBrokerPeerTest, ConfiguredRunAsUidWithValidPidIsAllowed) {
    EXPECT_TRUE(sx::comm::stream::unix_peer_allowed(42, 1000, {0, 1000}));
}

TEST(CliBrokerPeerTest, ForeignUidIsRejected) {
    EXPECT_FALSE(sx::comm::stream::unix_peer_allowed(42, 2000, {0, 1000}));
}

TEST(CliBrokerPeerTest, RootIsRejectedWhenNotExplicitlyAllowed) {
    EXPECT_FALSE(sx::comm::stream::unix_peer_allowed(42, 0, {1000}));
}

TEST(CliBrokerPeerTest, ZeroPidIsRejectedForTrustedUid) {
    EXPECT_FALSE(sx::comm::stream::unix_peer_allowed(0, 1000, {0, 1000}));
}

TEST(CliBrokerPeerTest, NegativePidIsRejectedForRoot) {
    EXPECT_FALSE(sx::comm::stream::unix_peer_allowed(-1, 0, {0, 1000}));
}

TEST(CliBrokerPeerTest, EmptyAllowListRejectsValidPeer) {
    EXPECT_FALSE(sx::comm::stream::unix_peer_allowed(42, 0, {}));
}

TEST(CliBrokerTest, PublicUnixSocketRelaysWhileTcpConsoleIsDisabled) {
    char directory_template[] = "./smithproxy-cli-public-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    const std::string socket_path = std::string(directory) + "/cli.sock";
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::cli::start_internal_broker(
        port, socket_path, ::geteuid(), ::getegid(), false), 0);

    const int client = connect_unix_socket(socket_path);
    ASSERT_GE(client, 0);
    EXPECT_EQ(connect_loopback(port), -1);

    const int listener = sx::comm::cli::ingress_fd();
    ASSERT_GE(listener, 0);
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    ASSERT_TRUE(sx::comm::cli::receive_handshake(core));
    ASSERT_EQ(::send(client, "unix", 4, MSG_NOSIGNAL), 4);
    std::array<char, 8> data {};
    ASSERT_EQ(::read(core, data.data(), data.size()), 4);
    EXPECT_EQ(std::string_view(data.data(), 4), "unix");

    const auto permissions = std::filesystem::status(socket_path).permissions();
    EXPECT_NE(permissions & std::filesystem::perms::owner_read,
              std::filesystem::perms::none);
    EXPECT_NE(permissions & std::filesystem::perms::group_write,
              std::filesystem::perms::none);
    EXPECT_EQ(permissions & std::filesystem::perms::others_all,
              std::filesystem::perms::none);

    ::close(core);
    ::close(listener);
    ::close(client);
    EXPECT_EQ(sx::comm::cli::stop_broker(), 0);
    EXPECT_FALSE(std::filesystem::exists(socket_path));
    EXPECT_EQ(::rmdir(directory), 0);
}

TEST(CliBrokerTest, PublicUnixSocketRejectsForeignUidAfterConnect) {
    if(::geteuid() != 0) {
        GTEST_SKIP() << "dropping privileges requires root";
    }

    const passwd* foreign_user = ::getpwnam("nobody");
    ASSERT_NE(foreign_user, nullptr);
    ASSERT_NE(foreign_user->pw_uid, 0U);

    char directory_template[] = "./smithproxy-cli-peer-test-XXXXXX";
    char* directory = ::mkdtemp(directory_template);
    ASSERT_NE(directory, nullptr);
    ASSERT_EQ(::chmod(directory, 0777), 0);

    const std::string socket_path = std::string(directory) + "/cli.sock";
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::cli::start_internal_broker(
        port, socket_path, 0, foreign_user->pw_gid, false), 0);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        if(::setgid(foreign_user->pw_gid) != 0 ||
           ::setuid(foreign_user->pw_uid) != 0) {
            ::_exit(2);
        }

        const int client = connect_unix_socket(socket_path);
        if(client < 0) ::_exit(3);

        static constexpr std::string_view payload = "untrusted command\n";
        const ssize_t sent = ::send(
            client, payload.data(), payload.size(), MSG_NOSIGNAL);
        if(sent < 0 && errno != EPIPE && errno != ECONNRESET) ::_exit(4);

        char byte = 0;
        const ssize_t received = ::read(client, &byte, sizeof(byte));
        const bool closed_cleanly = received == 0;
        const bool connection_reset = received < 0 && errno == ECONNRESET;
        const bool rejected = closed_cleanly || connection_reset;
        ::close(client);
        ::_exit(rejected ? EXIT_SUCCESS : 5);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);

    for(unsigned attempt = 0;
        attempt < 100 && sx::comm::cli::stats().rejected == 0;
        ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto stats = sx::comm::cli::stats();
    EXPECT_EQ(stats.accepted, 1);
    EXPECT_EQ(stats.rejected, 1);
    EXPECT_EQ(stats.core_connect_errors, 0);
    EXPECT_EQ(stats.active, 0);

    const int listener = sx::comm::cli::ingress_fd();
    ASSERT_GE(listener, 0);
    pollfd core_listener {listener, POLLIN, 0};
    ASSERT_EQ(::poll(&core_listener, 1, 100), 0)
        << "an unauthorized peer reached the CLI core";
    ::close(listener);
    EXPECT_EQ(sx::comm::cli::stop_broker(), 0);
    EXPECT_FALSE(std::filesystem::exists(socket_path));
    EXPECT_EQ(::rmdir(directory), 0);
}

unsigned long long process_cpu_ticks(pid_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    std::getline(input, line);
    if(line.empty()) return ~0ULL;
    std::istringstream fields(line.substr(line.rfind(')') + 2));
    std::string field;
    for(unsigned i = 3; i < 14; ++i) fields >> field;
    unsigned long long user = 0, system = 0;
    fields >> user >> system;
    return user + system;
}

void check_disconnected_broker(bool reset_client) {
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::cli::start_internal_broker(port), 0);
    const int tcp = connect_loopback(port);
    ASSERT_GE(tcp, 0);
    const int listener = sx::comm::cli::ingress_fd();
    const int core = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    ASSERT_GE(core, 0);
    ASSERT_TRUE(sx::comm::cli::receive_handshake(core));
    if(reset_client) {
        // Abort with TCP RST while the core side deliberately stays open.
        linger reset{1, 0};
        ASSERT_EQ(::setsockopt(tcp, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)), 0);
        ::close(tcp);
    } else {
        // Core console closes while the detached TCP client remains connected.
        ::close(core);
    }
    for(unsigned i = 0; i < 100 && sx::comm::cli::stats().completed == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_EQ(sx::comm::cli::stats().active, 0);
    EXPECT_EQ(sx::comm::cli::stats().completed, 1);
    const auto pid = sx::comm::cli::internal_broker_pid();
    const auto task_path = "/proc/" + std::to_string(pid) + "/task";
    auto thread_count = [&] {
        return std::distance(std::filesystem::directory_iterator(task_path),
                             std::filesystem::directory_iterator{});
    };
    for(unsigned i = 0; i < 100 && thread_count() != 1; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_EQ(thread_count(), 1);
    const auto before = process_cpu_ticks(pid);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto after = process_cpu_ticks(pid);
    EXPECT_NE(before, ~0ULL);
    EXPECT_NE(after, ~0ULL);
    // Allow scheduler/accounting noise, but reject a spinning core (~50 ticks).
    EXPECT_LE(after - before, static_cast<unsigned long long>(::sysconf(_SC_CLK_TCK) / 20));
    ::testing::Test::RecordProperty("idle_cpu_ticks", std::to_string(after - before));
    if(reset_client) ::close(core);
    else ::close(tcp);
    ::close(listener);
    EXPECT_EQ(sx::comm::cli::stop_broker(), 0);
}

TEST(CliBrokerTest, AbruptClientDisconnectReapsWorkerAndReturnsToIdle) {
    check_disconnected_broker(true);
}

TEST(CliBrokerTest, ClosedCoreConsoleReapsWorkerAndReturnsToIdle) {
    check_disconnected_broker(false);
}

TEST(CliBrokerTest, InternalBrokerStopsWhenSigtermIsBlocked) {
    sigset_t blocked{};
    sigset_t previous{};
    ASSERT_EQ(::sigemptyset(&blocked), 0);
    ASSERT_EQ(::sigaddset(&blocked, SIGTERM), 0);
    ASSERT_EQ(::pthread_sigmask(SIG_BLOCK, &blocked, &previous), 0);
    const auto port = unused_loopback_port();
    ASSERT_NE(port, 0);
    ASSERT_EQ(sx::comm::cli::start_internal_broker(port), 0);
    EXPECT_EQ(sx::comm::cli::stop_broker(), 0);
    EXPECT_EQ(::pthread_sigmask(SIG_SETMASK, &previous, nullptr), 0);
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
    EXPECT_EQ(std::filesystem::status(path).permissions()
                  & (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
              std::filesystem::perms::none);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        sx::comm::cli::CliBrokerServer server(
            {"127.0.0.1", port, path, sx::comm::cli::handshake(), {"*"}, {}, 256});
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
