#pragma once

#include "administrator_authenticator.hpp"

#include <atomic>
#include <filesystem>
#include <functional>
#include <string_view>
#include <thread>

namespace sx::admin {

class AuthSocket {
public:
    using Authenticate = std::function<LoginResult(
        std::string_view source,
        std::string_view username,
        std::string_view password)>;
    using Log = std::function<void(bool warning, std::string_view message)>;

    explicit AuthSocket(
        std::filesystem::path path,
        Authenticate authenticate,
        Log log = {});
    ~AuthSocket();

    bool start();
    void stop() noexcept;
    [[nodiscard]] bool running() const noexcept { return running_.load(); }

    AuthSocket(const AuthSocket&) = delete;
    AuthSocket& operator=(const AuthSocket&) = delete;

private:
    void serve() noexcept;
    void serve_client(int descriptor) noexcept;
    void report(bool warning, std::string_view message) const;
    bool remove_owned_socket() const noexcept;

    std::filesystem::path path_;
    Authenticate authenticate_;
    Log log_;
    std::thread worker_;
    std::atomic_bool running_ {false};
    std::atomic_bool stopping_ {false};
    std::atomic_int listener_ {-1};
    std::uintmax_t socket_device_ {0};
    std::uintmax_t socket_inode_ {0};
};

} // namespace sx::admin
