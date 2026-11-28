#pragma once

#include "administrator_authenticator.hpp"

#include <atomic>
#include <cstdint>
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

    // Creates a local JSON authentication endpoint. The callback owns the
    // authentication policy; this class owns only transport and lifecycle.
    explicit AuthSocket(std::filesystem::path path, Authenticate authenticate, Log log = {});
    ~AuthSocket();

    // Publishes the Unix socket and starts its worker. Returns false when the
    // path, containing directory or existing socket cannot be trusted.
    bool start();

    // Stops the worker and removes only the socket inode created by this object.
    void stop() noexcept;
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] std::uint64_t invalid_requests() const noexcept {
        return invalid_requests_.load();
    }

    AuthSocket(const AuthSocket&) = delete;
    AuthSocket& operator=(const AuthSocket&) = delete;

private:
    // Accepts local requests until stop() closes the listening descriptor.
    void serve() noexcept;

    // Processes one bounded JSON request and always returns a generic response
    // that does not expose parser, credential or backend failure details.
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
    std::atomic_uint64_t invalid_requests_ {0};
    std::uintmax_t socket_device_ {0};
    std::uintmax_t socket_inode_ {0};
};

} // namespace sx::admin
