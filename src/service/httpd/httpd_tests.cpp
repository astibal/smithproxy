#include <gtest/gtest.h>

#include <service/httpd/httpd.hpp>

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <set>
#include <sys/socket.h>

namespace {

using sx::webserver::HttpSessions;
using sx::webserver::TimedOptional;

std::set<int> listening_sockets() {
    std::set<int> result;
    std::error_code error;
    for(std::filesystem::directory_iterator entry("/proc/self/fd", error), end;
        not error && entry != end; entry.increment(error)) {
        auto const name = entry->path().filename().string();
        char* tail = nullptr;
        errno = 0;
        auto const value = std::strtol(name.c_str(), &tail, 10);
        if(errno or tail == name.c_str() or *tail != '\0' or value < 0) continue;

        int accepting = 0;
        socklen_t accepting_size = sizeof(accepting);
        if(::getsockopt(static_cast<int>(value), SOL_SOCKET, SO_ACCEPTCONN,
                        &accepting, &accepting_size) == 0 && accepting) {
            result.emplace(static_cast<int>(value));
        }
    }
    return result;
}

std::set<int> new_listening_sockets(std::set<int> const& before) {
    auto const after = listening_sockets();
    std::set<int> result;
    std::set_difference(after.begin(), after.end(), before.begin(), before.end(),
                        std::inserter(result, result.end()));
    return result;
}

unsigned short listening_port(int descriptor) {
    sockaddr_in address{};
    socklen_t size = sizeof(address);
    if(::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &size) != 0)
        return 0;
    return ntohs(address.sin_port);
}

int request_status(unsigned short port) {
    const int descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(descriptor < 0) return 0;
    timeval timeout{2, 0};
    ::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if(::connect(descriptor, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(descriptor);
        return 0;
    }
    constexpr std::string_view request =
        "GET /missing HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if(::send(descriptor, request.data(), request.size(), MSG_NOSIGNAL) !=
       static_cast<ssize_t>(request.size())) {
        ::close(descriptor);
        return 0;
    }
    std::array<char, 128> response{};
    const auto received = ::recv(descriptor, response.data(), response.size() - 1, 0);
    ::close(descriptor);
    if(received <= 0) return 0;
    int status = 0;
    return std::sscanf(response.data(), "HTTP/%*s %d", &status) == 1 ? status : 0;
}

class HttpSessionsTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::extend_on_access = false;
    }

    void TearDown() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::extend_on_access = true;
    }
};

TEST_F(HttpSessionsTest, ExpiredValuesAreRejectedAndRemoved) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf"] = TimedOptional<std::string>("token", 0);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf"), "");
    HttpSessions::cleanup();

    auto lock = std::scoped_lock(HttpSessions::lock);
    EXPECT_TRUE(HttpSessions::access_keys.empty());
}

TEST_F(HttpSessionsTest, ValidValuesAndApiKeySnapshotsRoundTrip) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf_token"] = TimedOptional<std::string>("token", 60);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf_token"), "token");
    EXPECT_TRUE(HttpSessions::validate_tokens("auth", "token"));

    HttpSessions::replace_api_keys({"one", "two"});
    EXPECT_TRUE(HttpSessions::has_api_keys());
    EXPECT_TRUE(HttpSessions::has_api_key("one"));
    EXPECT_FALSE(HttpSessions::has_api_key("missing"));
    EXPECT_EQ(HttpSessions::api_keys_snapshot(),
              (std::set<std::string>{"one", "two"}));
}

TEST(HttpResponderTest, AccumulatesBinaryPostChunksAndBoundsTheBody) {
    unsigned calls = 0;
    std::string received;
    auto callback = [&](MHD_Connection*, std::string const&, std::string const& body) {
        ++calls;
        received = body;
        sx::webserver::Http_JsonResponseParams result;
        result.response_code = 200;
        result.response = {{"ok", true}};
        return result;
    };
    sx::webserver::Http_Responder responder("POST", "/upload", callback);

    void* state = new lmh::ConnectionState(responder);
    std::stringstream response;
    const char first[] = {'a', '\0', 'b'};
    std::size_t first_size = sizeof(first);
    auto pending = responder.createResponse(nullptr, "/upload", "POST", first,
                                            &first_size, &state, response);
    EXPECT_EQ(pending.response_code, MHD_YES);
    EXPECT_EQ(first_size, 0U);
    EXPECT_EQ(calls, 0U);

    const char second[] = {'c', 'd'};
    std::size_t second_size = sizeof(second);
    responder.createResponse(nullptr, "/upload", "POST", second,
                             &second_size, &state, response);
    EXPECT_EQ(calls, 0U);

    std::size_t complete_size = 0;
    auto complete = responder.createResponse(nullptr, "/upload", "POST", nullptr,
                                             &complete_size, &state, response);
    EXPECT_EQ(complete.response_code, 200);
    EXPECT_EQ(calls, 1U);
    EXPECT_EQ(received, std::string(first, sizeof(first)) + std::string(second, sizeof(second)));
    delete static_cast<lmh::ConnectionState*>(state);

    calls = 0;
    state = new lmh::ConnectionState(responder);
    std::string oversized(8U * 1024U * 1024U + 1U, 'x');
    std::size_t oversized_size = oversized.size();
    responder.createResponse(nullptr, "/upload", "POST", oversized.data(),
                             &oversized_size, &state, response);
    complete_size = 0;
    auto rejected = responder.createResponse(nullptr, "/upload", "POST", nullptr,
                                             &complete_size, &state, response);
    EXPECT_EQ(rejected.response_code, 413);
    EXPECT_EQ(calls, 0U);
    delete static_cast<lmh::ConnectionState*>(state);
}


TEST(HttpDaemonLifecycle, ListenerIsCloseOnExecAndCanRestart) {
    auto const before = listening_sockets();
    lmh::WebServer server(0);
    server.options().bind_loopback = true;

    server.start_daemon();
    ASSERT_TRUE(server.is_daemon_alive());
    auto first = new_listening_sockets(before);
    ASSERT_EQ(first.size(), 1U);
    EXPECT_NE(::fcntl(*first.begin(), F_GETFD) & FD_CLOEXEC, 0);

    server.stop_daemon();
    EXPECT_FALSE(server.is_daemon_alive());
    EXPECT_TRUE(new_listening_sockets(before).empty());

    server.start_daemon();
    ASSERT_TRUE(server.is_daemon_alive());
    auto second = new_listening_sockets(before);
    ASSERT_EQ(second.size(), 1U);
    EXPECT_NE(::fcntl(*second.begin(), F_GETFD) & FD_CLOEXEC, 0);
    server.stop_daemon();
}

TEST(HttpDaemonLifecycle, RepeatedEmptyErrorResponsesRemainUsable) {
    auto const before = listening_sockets();
    lmh::WebServer missing(0);
    missing.options().bind_loopback = true;
    missing.start_daemon();
    auto listener = new_listening_sockets(before);
    ASSERT_EQ(listener.size(), 1U);
    const auto missing_port = listening_port(*listener.begin());
    ASSERT_NE(missing_port, 0U);
    for(int i = 0; i < 64; ++i) EXPECT_EQ(request_status(missing_port), 404);
    missing.stop_daemon();

    lmh::WebServer forbidden(0);
    forbidden.options().bind_loopback = true;
    forbidden.options().allowed_ips = {"192.0.2.1"};
    forbidden.start_daemon();
    listener = new_listening_sockets(before);
    ASSERT_EQ(listener.size(), 1U);
    const auto forbidden_port = listening_port(*listener.begin());
    ASSERT_NE(forbidden_port, 0U);
    for(int i = 0; i < 64; ++i) EXPECT_EQ(request_status(forbidden_port), 403);
    forbidden.stop_daemon();
}


} // namespace
