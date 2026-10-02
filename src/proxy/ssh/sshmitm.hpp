/*
 * Non-blocking libssh transport for the Smithproxy SSH MITM.
 */

#ifndef SMITHPROXY_SSHMITM_HPP
#define SMITHPROXY_SSHMITM_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <proxy/ssh/sshprotocol.hpp>

class logan_lite;

namespace sx::ssh {

enum class drive_result {
    progress,
    again,
    finished,
    blocked,
    failed,
};

enum class authentication_method {
    unsupported,
    password,
};

[[nodiscard]] authentication_method classify_authentication_method(int subtype) noexcept;

enum class channel_request_kind {
    unsupported,
    pty,
    shell,
    exec,
    subsystem,
    environment,
    window_change,
    x11,
};

[[nodiscard]] channel_request_kind classify_channel_request(int subtype) noexcept;
[[nodiscard]] char const* channel_request_name(channel_request_kind kind) noexcept;
logan_lite& transport_log();
logan_lite& shell_log();
logan_lite& exec_log();

struct transport_options {
    struct feature_policy {
        bool shell = true;
        bool exec = true;
        bool subsystem = true;
        bool pty = true;
        bool environment = true;
        bool local_forward = true;
        bool remote_forward = true;
        bool x11 = true;
        bool agent = true;
    } features;
    std::string profile_name;
    std::string host_key;
    std::string upstream_host;
    std::function<void(bool upstream, std::string_view)> plaintext_observer;
    std::function<void(bool upstream, std::string_view)> event_observer;
};

class mitm_transport {
public:
    explicit mitm_transport(transport_options options);
    ~mitm_transport();

    mitm_transport(mitm_transport const&) = delete;
    mitm_transport& operator=(mitm_transport const&) = delete;

    // Both descriptors must refer to already connected TCP sockets. The
    // caller keeps ownership and must stop other readers before drive() is
    // called. libssh operates on private dup() descriptors.
    bool attach(int client_fd, int upstream_fd);
    drive_result drive();

    [[nodiscard]] mitm_state state() const noexcept;
    [[nodiscard]] std::string const& error() const noexcept;
    [[nodiscard]] identification const& server_identification() const noexcept;
    [[nodiscard]] identification const& client_identification() const noexcept;
    [[nodiscard]] std::uint64_t bytes_up() const noexcept;
    [[nodiscard]] std::uint64_t bytes_down() const noexcept;
    [[nodiscard]] std::string diagnostics() const;

private:
    class impl;
    std::unique_ptr<impl> impl_;
};

} // namespace sx::ssh

#endif
