#include <service/admin/auth_socket.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace {

class AdminAuthSocketTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto pattern = (std::filesystem::temp_directory_path() /
                        "smithproxy-admin-auth-XXXXXX").string();
        auto buffer = std::vector<char>(pattern.begin(), pattern.end());
        buffer.push_back('\0');
        const auto* created = ::mkdtemp(buffer.data());
        ASSERT_NE(created, nullptr);
        directory_ = created;
        socket_path_ = directory_ / "auth.sock";
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(directory_, error);
    }

    nlohmann::json exchange_payload(const std::string& payload) const {
        const int descriptor = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        EXPECT_GE(descriptor, 0);
        if(descriptor < 0) return {};

        sockaddr_un address {};
        address.sun_family = AF_UNIX;
        const auto path = socket_path_.string();
        std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
        const auto address_size = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + path.size() + 1U);
        EXPECT_EQ(::connect(
            descriptor, reinterpret_cast<const sockaddr*>(&address), address_size), 0);

        EXPECT_EQ(::send(descriptor, payload.data(), payload.size(), MSG_NOSIGNAL),
                  static_cast<ssize_t>(payload.size()));
        std::array<char, 4096> response {};
        const auto received = ::recv(descriptor, response.data(), response.size(), 0);
        EXPECT_GT(received, 0);
        ::close(descriptor);
        if(received <= 0) return {};
        return nlohmann::json::parse(response.data(), response.data() + received);
    }

    nlohmann::json exchange(const nlohmann::json& request) const {
        return exchange_payload(request.dump());
    }

    std::filesystem::path directory_;
    std::filesystem::path socket_path_;
};

TEST_F(AdminAuthSocketTest, ExchangesVersionedJsonWithoutExposingCredentials) {
    std::string observed_source;
    std::string observed_username;
    std::string observed_password;
    sx::admin::AuthSocket server(
        socket_path_,
        [&](const std::string_view source,
            const std::string_view username,
            const std::string_view password) {
            observed_source = source;
            observed_username = username;
            observed_password = password;
            return sx::admin::LoginResult{
                sx::admin::LoginStatus::accepted,
                "alice",
                "password",
                true,
            };
        });
    ASSERT_TRUE(server.start());

    const auto response = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", "alice"},
        {"password", "correct horse battery staple"},
    });

    EXPECT_EQ(response["version"], 1);
    EXPECT_EQ(response["status"], "accepted");
    EXPECT_EQ(response["identity"], "alice");
    EXPECT_EQ(response["authentication_method"], "password");
    EXPECT_EQ(response.dump().find("correct horse battery staple"), std::string::npos);
    EXPECT_EQ(observed_username, "alice");
    EXPECT_EQ(observed_password, "correct horse battery staple");
    EXPECT_EQ(observed_source, "unix:uid=" + std::to_string(::geteuid()));

    server.stop();
    EXPECT_FALSE(std::filesystem::exists(socket_path_));
}

TEST_F(AdminAuthSocketTest, RejectsUnknownAndOversizedRequestsWithoutAuthentication) {
    std::size_t authentication_calls = 0;
    sx::admin::AuthSocket server(
        socket_path_,
        [&](std::string_view, std::string_view, std::string_view) {
            ++authentication_calls;
            return sx::admin::LoginResult{
                sx::admin::LoginStatus::accepted, {}, {}, false, 0};
        });
    ASSERT_TRUE(server.start());

    const auto wrong_version = exchange({
        {"version", 2},
        {"operation", "authenticate"},
        {"username", "alice"},
        {"password", "password"},
    });
    EXPECT_EQ(wrong_version["status"], "invalid_request");

    const auto unknown_operation = exchange({
        {"version", 1},
        {"operation", "change_password"},
        {"username", "alice"},
        {"password", "password"},
    });
    EXPECT_EQ(unknown_operation["status"], "invalid_request");

    const auto oversized_username = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", std::string(256U, 'a')},
        {"password", "password"},
    });
    EXPECT_EQ(oversized_username["status"], "invalid_request");

    const auto oversized_packet = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", "alice"},
        {"password", std::string(5000U, 'p')},
    });
    EXPECT_EQ(oversized_packet["status"], "invalid_request");
    EXPECT_EQ(authentication_calls, 0U);
}

TEST_F(AdminAuthSocketTest, RejectsMalformedAndIncompleteJsonWithoutAuthentication) {
    std::size_t authentication_calls = 0;
    sx::admin::AuthSocket server(
        socket_path_,
        [&](std::string_view, std::string_view, std::string_view) {
            ++authentication_calls;
            return sx::admin::LoginResult{
                sx::admin::LoginStatus::accepted, {}, {}, false, 0};
        });
    ASSERT_TRUE(server.start());

    const auto malformed = exchange_payload("{not-json");
    EXPECT_EQ(malformed["status"], "invalid_request");

    const auto missing_password = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", "alice"},
    });
    EXPECT_EQ(missing_password["status"], "invalid_request");

    const auto wrong_password_type = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", "alice"},
        {"password", 42},
    });
    EXPECT_EQ(wrong_password_type["status"], "invalid_request");

    const auto empty_username = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", ""},
        {"password", "password"},
    });
    EXPECT_EQ(empty_username["status"], "invalid_request");

    const auto empty_password = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", "alice"},
        {"password", ""},
    });
    EXPECT_EQ(empty_password["status"], "invalid_request");
    EXPECT_EQ(authentication_calls, 0U);
}

TEST_F(AdminAuthSocketTest, PreservesThrottleResultInProtocol) {
    sx::admin::AuthSocket server(
        socket_path_,
        [](std::string_view, std::string_view, std::string_view) {
            return sx::admin::LoginResult{
                sx::admin::LoginStatus::throttled, {}, {}, false, 17};
        });
    ASSERT_TRUE(server.start());

    const auto response = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", "alice"},
        {"password", "password"},
    });

    EXPECT_EQ(response["status"], "throttled");
    EXPECT_EQ(response["retry_after_seconds"], 17);
}

TEST_F(AdminAuthSocketTest, DoesNotReplaceAnotherLiveServer) {
    const auto accepted = [](std::string_view, std::string_view, std::string_view) {
        return sx::admin::LoginResult{
            sx::admin::LoginStatus::accepted,
            "first-server",
            "password",
            true,
            0,
        };
    };
    sx::admin::AuthSocket first(socket_path_, accepted);
    sx::admin::AuthSocket second(socket_path_, accepted);
    ASSERT_TRUE(first.start());

    EXPECT_FALSE(second.start());
    const auto response = exchange({
        {"version", 1},
        {"operation", "authenticate"},
        {"username", "alice"},
        {"password", "password"},
    });
    EXPECT_EQ(response["status"], "accepted");
    EXPECT_EQ(response["identity"], "first-server");
}

TEST_F(AdminAuthSocketTest, RejectsUnsafeDirectoryWithoutChangingItsMode) {
    ASSERT_EQ(::chmod(directory_.c_str(), 0777), 0);
    sx::admin::AuthSocket server(
        socket_path_,
        [](std::string_view, std::string_view, std::string_view) {
            return sx::admin::LoginResult{
                sx::admin::LoginStatus::accepted, {}, {}, false, 0};
        });

    EXPECT_FALSE(server.start());
    EXPECT_FALSE(std::filesystem::exists(socket_path_));

    struct stat metadata {};
    ASSERT_EQ(::stat(directory_.c_str(), &metadata), 0);
    EXPECT_EQ(metadata.st_mode & 0777, 0777);
}

} // namespace
