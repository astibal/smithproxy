/*
 * Non-blocking libssh transport for the Smithproxy SSH MITM.
 */

#include <proxy/ssh/sshmitm.hpp>

#include <cerrno>
#include <cstring>
#include <utility>

#include <sys/socket.h>
#include <unistd.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

namespace sx::ssh {

namespace {

constexpr std::size_t peek_buffer_size = 8192;

class peek_reader {
public:
    parse_status read(int fd, identification_parser& parser, std::string& error) {
        char data[peek_buffer_size];
        auto const count = ::recv(fd, data, sizeof(data), MSG_PEEK | MSG_DONTWAIT);
        if (count == 0) {
            error = "SSH peer closed during identification";
            return parse_status::invalid;
        }
        if (count < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return parse_status::need_more;
            }
            error = std::string("cannot peek SSH identification: ") + std::strerror(errno);
            return parse_status::invalid;
        }

        auto const available = static_cast<std::size_t>(count);
        if (available < observed_) {
            error = "SSH identification changed while being inspected";
            return parse_status::invalid;
        }
        if (available == observed_) {
            return parse_status::need_more;
        }

        auto const result = parser.feed(
            std::string_view(data + observed_, available - observed_));
        observed_ = available;
        if (result == parse_status::invalid && error.empty()) {
            error = parser.error();
        }
        return result;
    }

private:
    std::size_t observed_ = 0;
};

std::string libssh_error(void* object, char const* operation) {
    auto const* detail = ssh_get_error(object);
    return std::string(operation) + ": " + (detail ? detail : "unknown libssh error");
}

} // namespace

class mitm_transport::impl {
public:
    explicit impl(transport_options options) : options_(std::move(options)) {}

    ~impl() {
        if (downstream_) {
            ssh_disconnect(downstream_);
            ssh_free(downstream_);
        }
        if (upstream_) {
            ssh_disconnect(upstream_);
            ssh_free(upstream_);
        }
        if (bind_) {
            ssh_bind_free(bind_);
        }
        if (client_fd_ >= 0) {
            ::close(client_fd_);
        }
        if (upstream_fd_ >= 0) {
            ::close(upstream_fd_);
        }
    }

    bool attach(int client_fd, int upstream_fd) {
        if (client_fd_ >= 0 || upstream_fd_ >= 0) {
            set_error("SSH transport is already attached");
            return false;
        }
        client_fd_ = ::dup(client_fd);
        if (client_fd_ < 0) {
            set_error(std::string("cannot duplicate SSH client socket: ") + std::strerror(errno));
            return false;
        }
        upstream_fd_ = ::dup(upstream_fd);
        if (upstream_fd_ < 0) {
            set_error(std::string("cannot duplicate SSH upstream socket: ") + std::strerror(errno));
            return false;
        }
        return true;
    }

    drive_result drive() {
        switch (fsm_.state()) {
            case mitm_state::detect:
                return fsm_.begin_upstream_connect()
                    ? drive_result::progress : drive_result::failed;

            case mitm_state::upstream_connect:
                if (client_fd_ < 0 || upstream_fd_ < 0) {
                    set_error("SSH transport has no attached sockets");
                    return drive_result::failed;
                }
                return fsm_.upstream_connected()
                    ? drive_result::progress : drive_result::failed;

            case mitm_state::server_identification:
                return drive_identification(
                    upstream_fd_, server_peek_, server_parser(), true);

            case mitm_state::client_identification:
                return drive_identification(
                    client_fd_, client_peek_, client_parser(), false);

            case mitm_state::key_exchange:
                return drive_key_exchange();

            case mitm_state::authentication:
                return drive_result::authentication_ready;

            case mitm_state::blocked:
                return drive_result::blocked;

            case mitm_state::failed:
            case mitm_state::closing:
            case mitm_state::closed:
            case mitm_state::channels:
                return drive_result::failed;
        }
        return drive_result::failed;
    }

    [[nodiscard]] identification_parser& server_parser() noexcept {
        return server_parser_;
    }
    [[nodiscard]] identification_parser& client_parser() noexcept {
        return client_parser_;
    }

    drive_result drive_identification(
            int fd,
            peek_reader& reader,
            identification_parser& parser,
            bool server) {
        std::string peek_error;
        auto const status = reader.read(fd, parser, peek_error);
        if (status == parse_status::need_more) {
            return drive_result::again;
        }
        if (status == parse_status::invalid) {
            set_error(peek_error.empty() ? parser.error() : peek_error);
            return drive_result::failed;
        }

        auto const fsm_status = server
            ? fsm_.feed_server_identification(parser.result().raw + "\r\n")
            : fsm_.feed_client_identification(parser.result().raw + "\r\n");
        if (fsm_status == parse_status::invalid) {
            error_ = fsm_.error();
            return drive_result::failed;
        }
        if (fsm_.state() == mitm_state::blocked) {
            error_ = fsm_.error();
            return drive_result::blocked;
        }
        return drive_result::progress;
    }

    bool initialize_sessions() {
        upstream_ = ssh_new();
        downstream_ = ssh_new();
        bind_ = ssh_bind_new();
        if (!upstream_ || !downstream_ || !bind_) {
            set_error("cannot allocate libssh sessions");
            return false;
        }

        int const process_config = 0;
        if (ssh_options_set(upstream_, SSH_OPTIONS_PROCESS_CONFIG,
                            &process_config) != SSH_OK) {
            set_error(libssh_error(upstream_, "cannot disable upstream SSH config processing"));
            return false;
        }
        if (ssh_bind_options_set(bind_, SSH_BIND_OPTIONS_PROCESS_CONFIG,
                                 &process_config) != SSH_OK) {
            set_error(libssh_error(bind_, "cannot disable SSH server config processing"));
            return false;
        }

        if (options_.host_key.empty()) {
            set_error("SSH MITM host key is not configured");
            return false;
        }
        if (ssh_bind_options_set(bind_, SSH_BIND_OPTIONS_HOSTKEY,
                                 options_.host_key.c_str()) != SSH_OK) {
            set_error(libssh_error(bind_, "cannot configure SSH MITM host key"));
            return false;
        }

        auto const& banner = fsm_.server_identification().raw;
        if (ssh_bind_options_set(bind_, SSH_BIND_OPTIONS_BANNER,
                                 banner.c_str()) != SSH_OK) {
            set_error(libssh_error(bind_, "cannot mirror upstream SSH banner"));
            return false;
        }

        if (!options_.upstream_host.empty()
            && ssh_options_set(upstream_, SSH_OPTIONS_HOST,
                               options_.upstream_host.c_str()) != SSH_OK) {
            set_error(libssh_error(upstream_, "cannot set upstream SSH host"));
            return false;
        }
        if (ssh_options_set(upstream_, SSH_OPTIONS_FD, &upstream_fd_) != SSH_OK) {
            set_error(libssh_error(upstream_, "cannot attach upstream SSH socket"));
            return false;
        }

        ssh_set_blocking(upstream_, 0);
        ssh_set_blocking(downstream_, 0);
        if (ssh_bind_accept_fd(bind_, downstream_, client_fd_) != SSH_OK) {
            set_error(libssh_error(bind_, "cannot attach downstream SSH socket"));
            return false;
        }

        // Ownership has moved to the two libssh sessions.
        upstream_fd_ = -1;
        client_fd_ = -1;
        initialized_ = true;
        return true;
    }

    drive_result drive_key_exchange() {
        if (!initialized_ && !initialize_sessions()) {
            return drive_result::failed;
        }

        if (!upstream_kex_done_) {
            auto const result = ssh_connect(upstream_);
            if (result == SSH_OK) {
                upstream_kex_done_ = true;
            } else if (result != SSH_AGAIN) {
                set_error(libssh_error(upstream_, "upstream SSH key exchange failed"));
                return drive_result::failed;
            }
        }

        if (!downstream_kex_done_) {
            auto const result = ssh_handle_key_exchange(downstream_);
            if (result == SSH_OK) {
                downstream_kex_done_ = true;
            } else if (result != SSH_AGAIN) {
                set_error(libssh_error(downstream_, "downstream SSH key exchange failed"));
                return drive_result::failed;
            }
        }

        if (!upstream_kex_done_ || !downstream_kex_done_) {
            return drive_result::again;
        }
        if (!fsm_.key_exchange_complete()) {
            error_ = fsm_.error();
            return drive_result::failed;
        }
        return drive_result::authentication_ready;
    }

    void set_error(std::string error) {
        error_ = std::move(error);
        fsm_.fail(error_);
    }

    transport_options options_;
    handshake_fsm fsm_;
    identification_parser server_parser_{true};
    identification_parser client_parser_{false};
    peek_reader server_peek_;
    peek_reader client_peek_;
    std::string error_;

    int client_fd_ = -1;
    int upstream_fd_ = -1;
    ssh_bind bind_ = nullptr;
    ssh_session downstream_ = nullptr;
    ssh_session upstream_ = nullptr;
    bool initialized_ = false;
    bool downstream_kex_done_ = false;
    bool upstream_kex_done_ = false;
};

mitm_transport::mitm_transport(transport_options options)
    : impl_(std::make_unique<impl>(std::move(options))) {}

mitm_transport::~mitm_transport() = default;

bool mitm_transport::attach(int client_fd, int upstream_fd) {
    return impl_->attach(client_fd, upstream_fd);
}

drive_result mitm_transport::drive() {
    return impl_->drive();
}

mitm_state mitm_transport::state() const noexcept {
    return impl_->fsm_.state();
}

std::string const& mitm_transport::error() const noexcept {
    return impl_->error_.empty() ? impl_->fsm_.error() : impl_->error_;
}

identification const& mitm_transport::server_identification() const noexcept {
    return impl_->fsm_.server_identification();
}

identification const& mitm_transport::client_identification() const noexcept {
    return impl_->fsm_.client_identification();
}

} // namespace sx::ssh
