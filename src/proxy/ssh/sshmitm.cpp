/*
 * Non-blocking libssh transport for the Smithproxy SSH MITM.
 */

#include <proxy/ssh/sshmitm.hpp>

#include <cerrno>
#include <algorithm>
#include <cstring>
#include <utility>

#include <sys/socket.h>
#include <unistd.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <display.hpp>
#include <log/logan.hpp>

namespace sx::ssh {

logan_lite& transport_log() {
    static logan_lite instance{"com.ssh"};
    return instance;
}

logan_lite& shell_log() {
    static logan_lite instance{"com.ssh.shell"};
    return instance;
}

logan_lite& exec_log() {
    static logan_lite instance{"com.ssh.exec"};
    return instance;
}

authentication_method classify_authentication_method(int subtype) noexcept {
    return subtype == SSH_AUTH_METHOD_PASSWORD
        ? authentication_method::password
        : authentication_method::unsupported;
}

channel_request_kind classify_channel_request(int subtype) noexcept {
    switch (subtype) {
        case SSH_CHANNEL_REQUEST_PTY:           return channel_request_kind::pty;
        case SSH_CHANNEL_REQUEST_SHELL:         return channel_request_kind::shell;
        case SSH_CHANNEL_REQUEST_EXEC:          return channel_request_kind::exec;
        case SSH_CHANNEL_REQUEST_SUBSYSTEM:     return channel_request_kind::subsystem;
        case SSH_CHANNEL_REQUEST_ENV:           return channel_request_kind::environment;
        case SSH_CHANNEL_REQUEST_WINDOW_CHANGE: return channel_request_kind::window_change;
        default:                                return channel_request_kind::unsupported;
    }
}

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

// The callback server API cannot suspend an authentication callback while the
// non-blocking upstream leg returns SSH_AUTH_AGAIN. Keep the deprecated getter
// isolated here until libssh exposes an asynchronous credential accessor.
char const* message_auth_password(ssh_message message) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    auto const* password = ssh_message_auth_password(message);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    return password;
}

void clear_secret(std::string& secret) {
    std::fill(secret.begin(), secret.end(), '\0');
    secret.clear();
}

struct pty_request {
    std::string terminal;
    int columns = 0;
    int rows = 0;
};

pty_request message_pty_request(ssh_message message) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    auto const* terminal = ssh_message_channel_request_pty_term(message);
    pty_request request{
        terminal ? terminal : "xterm",
        ssh_message_channel_request_pty_width(message),
        ssh_message_channel_request_pty_height(message),
    };
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    return request;
}

} // namespace

class mitm_transport::impl {
public:
    explicit impl(transport_options options) : options_(std::move(options)) {}

    ~impl() {
        auto const failed = fsm_.state() == mitm_state::failed;
        if (pending_auth_message_) {
            ssh_message_free(pending_auth_message_);
        }
        clear_secret(pending_password_);
        if (pending_channel_message_) {
            ssh_message_free(pending_channel_message_);
        }
        if (pending_open_message_) {
            ssh_message_free(pending_open_message_);
        }
        if (downstream_channel_) {
            ssh_channel_free(downstream_channel_);
        }
        if (upstream_channel_) {
            ssh_channel_free(upstream_channel_);
        }
        if (downstream_) {
            // Do not drive an already failed libssh state machine from a
            // destructor. ssh_free() still releases all session resources.
            if (!failed && ssh_is_connected(downstream_)) {
                ssh_disconnect(downstream_);
            }
            ssh_free(downstream_);
        }
        if (upstream_) {
            if (!failed && ssh_is_connected(upstream_)) {
                ssh_disconnect(upstream_);
            }
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
        xdia(transport_log())("attached client_fd=%d upstream_fd=%d", client_fd, upstream_fd);
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
                return drive_authentication();

            case mitm_state::blocked:
                return drive_result::blocked;

            case mitm_state::failed:
                return drive_result::failed;

            case mitm_state::closed:
                return drive_result::finished;

            case mitm_state::channels:
                return drive_channels();

            case mitm_state::closing:
                return drive_closing();
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
        ssh_set_auth_methods(downstream_, SSH_AUTH_METHOD_PASSWORD);
        if (ssh_bind_accept_fd(bind_, downstream_, client_fd_) != SSH_OK) {
            set_error(libssh_error(bind_, "cannot attach downstream SSH socket"));
            return false;
        }

        // Ownership has moved to the two libssh sessions.
        upstream_fd_ = -1;
        client_fd_ = -1;
        initialized_ = true;
        xdia(transport_log())("libssh sessions initialized, mirrored banner='%s'",
                              banner.c_str());
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
        xdia(transport_log())("key exchange complete on both SSH legs");
        return drive_result::progress;
    }

    drive_result reject_message(ssh_message message, bool authentication) {
        if (authentication) {
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
        }
        if (ssh_message_reply_default(message) != SSH_OK) {
            set_error(libssh_error(downstream_, "cannot reject SSH request"));
            ssh_message_free(message);
            return drive_result::failed;
        }
        ssh_message_free(message);
        return drive_result::progress;
    }

    drive_result drive_authentication() {
        if (pending_auth_message_) {
            auto const result = ssh_userauth_password(
                upstream_, pending_username_.c_str(), pending_password_.c_str());
            if (result == SSH_AUTH_AGAIN) {
                return drive_result::again;
            }

            auto* message = std::exchange(pending_auth_message_, nullptr);
            clear_secret(pending_password_);
            if (result == SSH_AUTH_SUCCESS) {
                if (ssh_message_auth_reply_success(message, 0) != SSH_OK) {
                    set_error(libssh_error(downstream_, "cannot accept SSH authentication"));
                    ssh_message_free(message);
                    return drive_result::failed;
                }
                ssh_message_free(message);
                xdia(transport_log())("upstream password authentication accepted for user='%s'",
                                      pending_username_.c_str());
                pending_username_.clear();
                if (!fsm_.authentication_complete()) {
                    error_ = fsm_.error();
                    return drive_result::failed;
                }
                return drive_result::progress;
            }

            if (result == SSH_AUTH_ERROR) {
                set_error(libssh_error(upstream_, "upstream SSH authentication failed"));
                ssh_message_free(message);
                pending_username_.clear();
                return drive_result::failed;
            }

            xdia(transport_log())("upstream password authentication rejected for user='%s'",
                                  pending_username_.c_str());
            pending_username_.clear();
            return reject_message(message, true);
        }

        auto* message = ssh_message_get(downstream_);
        if (!message) {
            return drive_result::again;
        }

        if (ssh_message_type(message) == SSH_REQUEST_SERVICE) {
            auto const* service = ssh_message_service_service(message);
            if (service && std::strcmp(service, "ssh-userauth") == 0
                && ssh_message_service_reply_success(message) == SSH_OK) {
                ssh_message_free(message);
                return drive_result::progress;
            }
            return reject_message(message, false);
        }

        if (ssh_message_type(message) != SSH_REQUEST_AUTH
            || classify_authentication_method(ssh_message_subtype(message))
                   != authentication_method::password) {
            return reject_message(message, ssh_message_type(message) == SSH_REQUEST_AUTH);
        }

        auto const* username = ssh_message_auth_user(message);
        auto const* password = message_auth_password(message);
        if (!username || !password) {
            return reject_message(message, true);
        }

        pending_username_ = username;
        pending_password_ = password;
        pending_auth_message_ = message;
        xdeb(transport_log())("password authentication requested for user='%s'",
                              pending_username_.c_str());
        return drive_authentication();
    }

    drive_result drive_channel_open() {
        if (!pending_open_message_) {
            auto* message = ssh_message_get(downstream_);
            if (!message) return drive_result::again;

            if (ssh_message_type(message) != SSH_REQUEST_CHANNEL_OPEN
                || ssh_message_subtype(message) != SSH_CHANNEL_SESSION
                || downstream_channel_ || upstream_channel_) {
                return reject_message(message, false);
            }

            upstream_channel_ = ssh_channel_new(upstream_);
            if (!upstream_channel_) {
                set_error(libssh_error(upstream_, "cannot allocate upstream SSH channel"));
                ssh_message_free(message);
                return drive_result::failed;
            }
            ssh_channel_set_blocking(upstream_channel_, 0);
            pending_open_message_ = message;
        }

        auto const result = ssh_channel_open_session(upstream_channel_);
        if (result == SSH_AGAIN) return drive_result::again;
        if (result != SSH_OK) {
            auto* message = std::exchange(pending_open_message_, nullptr);
            reject_message(message, false);
            set_error(libssh_error(upstream_, "cannot open upstream SSH session channel"));
            return drive_result::failed;
        }

        auto* message = std::exchange(pending_open_message_, nullptr);
        downstream_channel_ = ssh_message_channel_request_open_reply_accept(message);
        ssh_message_free(message);
        if (!downstream_channel_) {
            set_error(libssh_error(downstream_, "cannot accept downstream SSH session channel"));
            return drive_result::failed;
        }
        ssh_channel_set_blocking(downstream_channel_, 0);
        xdia(transport_log())("session channel opened on both SSH legs");
        return drive_result::progress;
    }

    int forward_channel_request(ssh_message message) {
        switch (classify_channel_request(ssh_message_subtype(message))) {
            case channel_request_kind::pty: {
                auto const request = message_pty_request(message);
                return ssh_channel_request_pty_size(upstream_channel_, request.terminal.c_str(),
                                                    request.columns, request.rows);
            }
            case channel_request_kind::shell:
                return ssh_channel_request_shell(upstream_channel_);
            case channel_request_kind::exec: {
                auto const* command = ssh_message_channel_request_command(message);
                return command ? ssh_channel_request_exec(upstream_channel_, command) : SSH_ERROR;
            }
            case channel_request_kind::subsystem: {
                auto const* subsystem = ssh_message_channel_request_subsystem(message);
                return subsystem ? ssh_channel_request_subsystem(upstream_channel_, subsystem) : SSH_ERROR;
            }
            case channel_request_kind::environment: {
                auto const* name = ssh_message_channel_request_env_name(message);
                auto const* value = ssh_message_channel_request_env_value(message);
                return name && value ? ssh_channel_request_env(upstream_channel_, name, value) : SSH_ERROR;
            }
            case channel_request_kind::window_change: {
                auto const request = message_pty_request(message);
                return ssh_channel_change_pty_size(upstream_channel_, request.columns, request.rows);
            }
            case channel_request_kind::unsupported:
                return SSH_ERROR;
        }
        return SSH_ERROR;
    }

    drive_result drive_channel_request() {
        if (!pending_channel_message_) {
            auto* message = ssh_message_get(downstream_);
            if (!message) return drive_result::again;
            if (ssh_message_type(message) != SSH_REQUEST_CHANNEL
                || ssh_message_channel_request_channel(message) != downstream_channel_
                || classify_channel_request(ssh_message_subtype(message))
                       == channel_request_kind::unsupported) {
                return reject_message(message, false);
            }
            pending_channel_message_ = message;
        }

        auto const result = forward_channel_request(pending_channel_message_);
        if (result == SSH_AGAIN) return drive_result::again;

        auto* message = std::exchange(pending_channel_message_, nullptr);
        if (result == SSH_OK) {
            auto const kind = classify_channel_request(ssh_message_subtype(message));
            if (kind == channel_request_kind::shell) {
                channel_mode_ = channel_mode::shell;
                xdia(transport_log())("interactive shell requested");
            } else if (kind == channel_request_kind::exec) {
                channel_mode_ = channel_mode::exec;
                auto const* command = ssh_message_channel_request_command(message);
                xdeb(exec_log())("request command='%s'", command ? command : "");
            } else if (kind == channel_request_kind::subsystem) {
                channel_mode_ = channel_mode::exec;
                auto const* subsystem = ssh_message_channel_request_subsystem(message);
                xdeb(exec_log())("request subsystem='%s'", subsystem ? subsystem : "");
            } else if (kind == channel_request_kind::environment) {
                auto const* name = ssh_message_channel_request_env_name(message);
                auto const* value = ssh_message_channel_request_env_value(message);
                xdeb(transport_log())("environment %s='%s'", name ? name : "", value ? value : "");
            } else if (kind == channel_request_kind::pty) {
                auto const request = message_pty_request(message);
                xdeb(transport_log())("pty term='%s' size=%dx%d", request.terminal.c_str(),
                                      request.columns, request.rows);
            } else if (kind == channel_request_kind::window_change) {
                auto const request = message_pty_request(message);
                xdeb(transport_log())("pty resize=%dx%d", request.columns, request.rows);
            }
            if (ssh_message_channel_request_reply_success(message) != SSH_OK) {
                ssh_message_free(message);
                set_error(libssh_error(downstream_, "cannot confirm downstream channel request"));
                return drive_result::failed;
            }
            ssh_message_free(message);
            return drive_result::progress;
        }
        return reject_message(message, false);
    }

    static int flush_channel_buffer(ssh_channel channel, std::string& pending, bool stderr_stream) {
        if (pending.empty()) return 0;
        auto const amount = stderr_stream
            ? ssh_channel_write_stderr(channel, pending.data(), pending.size())
            : ssh_channel_write(channel, pending.data(), pending.size());
        if (amount > 0) pending.erase(0, static_cast<std::size_t>(amount));
        return amount;
    }

    int read_channel(ssh_channel channel, std::string& pending, bool stderr_stream,
                     char const* direction, std::uint64_t& byte_counter,
                     bool upstream_direction) {
        if (!pending.empty()) return 0;
        char buffer[32768];
        auto const amount = ssh_channel_read_nonblocking(
            channel, buffer, sizeof(buffer), stderr_stream ? 1 : 0);
        if (amount > 0) {
            pending.assign(buffer, static_cast<std::size_t>(amount));
            byte_counter += static_cast<std::uint64_t>(amount);
            if (options_.plaintext_observer) {
                options_.plaintext_observer(upstream_direction, pending);
            }
            auto* payload_log = channel_mode_ == channel_mode::shell
                ? &shell_log()
                : channel_mode_ == channel_mode::exec ? &exec_log() : nullptr;
            if (payload_log && *payload_log->level() >= DEB) {
                payload_log->deb("%s%s %dB: %s", direction,
                                 stderr_stream ? " stderr" : "",
                                 amount, printable(pending).c_str());
            }
        }
        return amount;
    }

    drive_result drive_channel_data() {
        bool progress = false;
        auto flush = [&progress](ssh_channel channel, std::string& pending,
                                 bool stderr_stream) {
            auto const result = flush_channel_buffer(channel, pending, stderr_stream);
            if (result == SSH_ERROR) {
                return false;
            }
            progress = progress || result > 0;
            return true;
        };
        if (!flush(upstream_channel_, to_upstream_, false)
            || !flush(downstream_channel_, to_downstream_, false)
            || !flush(downstream_channel_, stderr_to_downstream_, true)) {
            set_error("SSH channel write failed");
            return drive_result::failed;
        }

        auto read = [this, &progress](ssh_channel channel, std::string& pending,
                                     bool stderr_stream, char const* direction,
                                     std::uint64_t& byte_counter, bool upstream_direction) {
            auto const result = read_channel(channel, pending, stderr_stream, direction,
                                             byte_counter, upstream_direction);
            if (result == SSH_ERROR) {
                return false;
            }
            progress = progress || result > 0;
            return true;
        };
        // Stop immediately on error. Further libssh calls on the same failed
        // session can invalidate channel state needed by teardown.
        if (!read(downstream_channel_, to_upstream_, false, "client->server", bytes_up_, true)
            || !read(upstream_channel_, to_downstream_, false, "server->client", bytes_down_, false)
            || !read(upstream_channel_, stderr_to_downstream_, true, "server->client", bytes_down_, false)) {
            set_error("SSH channel read failed");
            return drive_result::failed;
        }

        if (ssh_channel_is_eof(downstream_channel_) && !downstream_eof_forwarded_) {
            if (ssh_channel_send_eof(upstream_channel_) == SSH_ERROR) {
                set_error("cannot forward downstream SSH EOF");
                return drive_result::failed;
            }
            downstream_eof_forwarded_ = true;
            progress = true;
        }
        if (ssh_channel_is_eof(upstream_channel_) && !upstream_eof_forwarded_
            && to_downstream_.empty() && stderr_to_downstream_.empty()) {
            if (ssh_channel_send_eof(downstream_channel_) == SSH_ERROR) {
                set_error("cannot forward upstream SSH EOF");
                return drive_result::failed;
            }
            upstream_eof_forwarded_ = true;
            progress = true;
        }

        if ((ssh_channel_is_closed(upstream_channel_) || ssh_channel_is_closed(downstream_channel_))
            && to_upstream_.empty() && to_downstream_.empty() && stderr_to_downstream_.empty()) {
            if (!fsm_.begin_closing()) {
                error_ = fsm_.error();
                return drive_result::failed;
            }
            return drive_result::progress;
        }
        return progress ? drive_result::progress : drive_result::again;
    }

    drive_result drive_channels() {
        if (!downstream_channel_) return drive_channel_open();

        auto const request_result = drive_channel_request();
        if (request_result == drive_result::failed) return request_result;
        auto const data_result = drive_channel_data();
        if (data_result == drive_result::failed || data_result == drive_result::progress) {
            return data_result;
        }
        return request_result;
    }

    drive_result drive_closing() {
        if (upstream_channel_ && !ssh_channel_is_closed(upstream_channel_)) {
            auto const result = ssh_channel_close(upstream_channel_);
            if (result == SSH_AGAIN) return drive_result::again;
        }
        if (downstream_channel_ && !ssh_channel_is_closed(downstream_channel_)) {
            auto const result = ssh_channel_close(downstream_channel_);
            if (result == SSH_AGAIN) return drive_result::again;
        }
        if (!fsm_.close_complete()) {
            error_ = fsm_.error();
            return drive_result::failed;
        }
        xdia(transport_log())("SSH session channel closed");
        return drive_result::finished;
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
    ssh_message pending_auth_message_ = nullptr;
    std::string pending_username_;
    std::string pending_password_;
    ssh_message pending_open_message_ = nullptr;
    ssh_message pending_channel_message_ = nullptr;
    ssh_channel downstream_channel_ = nullptr;
    ssh_channel upstream_channel_ = nullptr;
    std::string to_upstream_;
    std::string to_downstream_;
    std::string stderr_to_downstream_;
    bool downstream_eof_forwarded_ = false;
    bool upstream_eof_forwarded_ = false;
    enum class channel_mode { none, shell, exec };
    channel_mode channel_mode_ = channel_mode::none;
    std::uint64_t bytes_up_ = 0;
    std::uint64_t bytes_down_ = 0;
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

std::uint64_t mitm_transport::bytes_up() const noexcept {
    return impl_->bytes_up_;
}

std::uint64_t mitm_transport::bytes_down() const noexcept {
    return impl_->bytes_down_;
}

} // namespace sx::ssh
