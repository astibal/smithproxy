/*
 * Non-blocking libssh transport for the Smithproxy SSH MITM.
 */

#ifndef SMITHPROXY_SSHMITM_HPP
#define SMITHPROXY_SSHMITM_HPP

#include <memory>
#include <string>

#include <proxy/ssh/sshprotocol.hpp>

namespace sx::ssh {

enum class drive_result {
    progress,
    again,
    authentication_ready,
    blocked,
    failed,
};

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

private:
    class impl;
    std::unique_ptr<impl> impl_;
};

} // namespace sx::ssh

#endif
