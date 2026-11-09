#include <gtest/gtest.h>

#include <array>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iterator>
#include <set>
#include <string>
#include <utility>

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include <libssh/libssh.h>
#include <log/logan.hpp>

#include <proxy/ssh/sshmitm.hpp>

namespace {

std::set<int> open_descriptors() {
    std::set<int> result;
    for (auto const& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
        auto const name = entry.path().filename().string();
        char* end = nullptr;
        auto const value = std::strtol(name.c_str(), &end, 10);
        if (end != name.c_str() && *end == '\0') result.insert(static_cast<int>(value));
    }
    for (auto it = result.begin(); it != result.end();) {
        if (::fcntl(*it, F_GETFD) < 0) it = result.erase(it);
        else ++it;
    }
    return result;
}

class socket_pair {
public:
    socket_pair() {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds_.data()) != 0) {
            fds_ = {-1, -1};
        }
    }
    ~socket_pair() {
        for (auto const fd : fds_) {
            if (fd >= 0) ::close(fd);
        }
    }

    [[nodiscard]] bool valid() const { return fds_[0] >= 0; }
    [[nodiscard]] int proxy_end() const { return fds_[0]; }

    void send(std::string const& value) const {
        ASSERT_EQ(::write(fds_[1], value.data(), value.size()),
                  static_cast<ssize_t>(value.size()));
    }

private:
    std::array<int, 2> fds_{-1, -1};
};

} // namespace

TEST(SshMitmTransport, DuplicatedTransportDescriptorsAreCloseOnExec) {
    socket_pair client;
    socket_pair server;
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(server.valid());

    auto const before = open_descriptors();
    auto options = sx::ssh::transport_options{};
    sx::ssh::mitm_transport transport(std::move(options));
    ASSERT_TRUE(transport.attach(client.proxy_end(), server.proxy_end()));
    auto const after = open_descriptors();

    std::vector<int> added;
    std::set_difference(after.begin(), after.end(), before.begin(), before.end(),
                        std::back_inserter(added));
    ASSERT_EQ(added.size(), 2U);
    for (auto const descriptor : added) {
        auto const flags = ::fcntl(descriptor, F_GETFD);
        ASSERT_GE(flags, 0);
        EXPECT_NE(flags & FD_CLOEXEC, 0);
    }
}

TEST(SshMitmTransport, PeeksAndPreservesBothIdentifications) {
    socket_pair client;
    socket_pair server;
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(server.valid());

    auto options = sx::ssh::transport_options{};
    options.host_key = "unused-before-kex";
    options.upstream_host = "server.test";
    sx::ssh::mitm_transport transport(std::move(options));
    ASSERT_TRUE(transport.attach(client.proxy_end(), server.proxy_end()));

    EXPECT_EQ(transport.drive(), sx::ssh::drive_result::progress);
    EXPECT_EQ(transport.drive(), sx::ssh::drive_result::progress);

    server.send("notice\r\nSSH-2.0-OpenSSH_9.8 real-server\r\n");
    EXPECT_EQ(transport.drive(), sx::ssh::drive_result::progress);
    EXPECT_EQ(transport.server_identification().raw,
              "SSH-2.0-OpenSSH_9.8 real-server");

    client.send("SSH-2.0-PuTTY_Release_0.83\r\n");
    EXPECT_EQ(transport.drive(), sx::ssh::drive_result::progress);
    EXPECT_EQ(transport.client_identification().raw,
              "SSH-2.0-PuTTY_Release_0.83");
    EXPECT_EQ(transport.state(), sx::ssh::mitm_state::key_exchange);
}

TEST(SshMitmTransport, BlocksSshOneBeforeLibsshTakesSocket) {
    socket_pair client;
    socket_pair server;
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(server.valid());

    auto options = sx::ssh::transport_options{};
    options.host_key = "unused-before-kex";
    options.upstream_host = "server.test";
    sx::ssh::mitm_transport transport(std::move(options));
    ASSERT_TRUE(transport.attach(client.proxy_end(), server.proxy_end()));
    ASSERT_EQ(transport.drive(), sx::ssh::drive_result::progress);
    ASSERT_EQ(transport.drive(), sx::ssh::drive_result::progress);

    server.send("SSH-1.5-legacy\r\n");
    EXPECT_EQ(transport.drive(), sx::ssh::drive_result::blocked);
    EXPECT_EQ(transport.state(), sx::ssh::mitm_state::blocked);
    EXPECT_EQ(transport.error(), "SSH protocol version 1 is blocked");
}

TEST(SshMitmTransport, InitiallySupportsOnlyPasswordAuthentication) {
    EXPECT_EQ(sx::ssh::classify_authentication_method(SSH_AUTH_METHOD_PASSWORD),
              sx::ssh::authentication_method::password);
    EXPECT_EQ(sx::ssh::classify_authentication_method(SSH_AUTH_METHOD_PUBLICKEY),
              sx::ssh::authentication_method::unsupported);
    EXPECT_EQ(sx::ssh::classify_authentication_method(SSH_AUTH_METHOD_INTERACTIVE),
              sx::ssh::authentication_method::unsupported);
}

TEST(SshMitmTransport, AppliesUpstreamHostKeyPolicies) {
    using sx::ssh::hostkey_decision;
    using sx::ssh::hostkey_policy;

    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::insecure, SSH_KNOWN_HOSTS_CHANGED),
              hostkey_decision::accept);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::accept_new, SSH_KNOWN_HOSTS_OK),
              hostkey_decision::accept);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::accept_new, SSH_KNOWN_HOSTS_UNKNOWN),
              hostkey_decision::learn);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::accept_new, SSH_KNOWN_HOSTS_NOT_FOUND),
              hostkey_decision::learn);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::accept_new, SSH_KNOWN_HOSTS_CHANGED),
              hostkey_decision::reject);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::accept_new, SSH_KNOWN_HOSTS_OTHER),
              hostkey_decision::reject);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::strict, SSH_KNOWN_HOSTS_OK),
              hostkey_decision::accept);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::strict, SSH_KNOWN_HOSTS_UNKNOWN),
              hostkey_decision::reject);
    EXPECT_EQ(sx::ssh::decide_hostkey(hostkey_policy::strict, SSH_KNOWN_HOSTS_ERROR),
              hostkey_decision::reject);
}

TEST(SshMitmTransport, ClassifiesSupportedSessionChannelRequests) {
    using sx::ssh::channel_request_kind;
    EXPECT_EQ(sx::ssh::classify_channel_request(SSH_CHANNEL_REQUEST_PTY),
              channel_request_kind::pty);
    EXPECT_EQ(sx::ssh::classify_channel_request(SSH_CHANNEL_REQUEST_SHELL),
              channel_request_kind::shell);
    EXPECT_EQ(sx::ssh::classify_channel_request(SSH_CHANNEL_REQUEST_EXEC),
              channel_request_kind::exec);
    EXPECT_EQ(sx::ssh::classify_channel_request(SSH_CHANNEL_REQUEST_SUBSYSTEM),
              channel_request_kind::subsystem);
    EXPECT_EQ(sx::ssh::classify_channel_request(SSH_CHANNEL_REQUEST_X11),
              channel_request_kind::x11);
    EXPECT_STREQ(sx::ssh::channel_request_name(channel_request_kind::pty), "pty");
    EXPECT_STREQ(sx::ssh::channel_request_name(channel_request_kind::shell), "shell");
    EXPECT_STREQ(sx::ssh::channel_request_name(channel_request_kind::exec), "exec");
    EXPECT_STREQ(sx::ssh::channel_request_name(channel_request_kind::subsystem), "subsystem");
    EXPECT_STREQ(sx::ssh::channel_request_name(channel_request_kind::environment), "environment");
    EXPECT_STREQ(sx::ssh::channel_request_name(channel_request_kind::window_change), "window-change");
    EXPECT_STREQ(sx::ssh::channel_request_name(channel_request_kind::x11), "x11");
}

TEST(SshMitmTransport, RegistersSeparateTransportAndPayloadLoggers) {
    EXPECT_EQ(sx::ssh::transport_log().topic(), "com.ssh");
    EXPECT_EQ(sx::ssh::shell_log().topic(), "com.ssh.shell");
    EXPECT_EQ(sx::ssh::exec_log().topic(), "com.ssh.exec");
}
