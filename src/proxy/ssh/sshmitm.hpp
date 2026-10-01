/*
 * Non-blocking libssh transport for the Smithproxy SSH MITM.
 */

#ifndef SMITHPROXY_SSHMITM_HPP
#define SMITHPROXY_SSHMITM_HPP

#include <cstdint>
#include <memory>
#include <string>

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
};

[[nodiscard]] channel_request_kind classify_channel_request(int subtype) noexcept;
logan_lite& transport_log();
logan_lite& shell_log();
logan_lite& exec_log();

struct transport_options {
    std::string host_key;
    std::string upstream_host;
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

private:
    class impl;
    std::unique_ptr<impl> impl_;
};

} // namespace sx::ssh

#endif
