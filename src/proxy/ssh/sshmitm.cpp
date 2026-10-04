/*
 * Non-blocking libssh transport for the Smithproxy SSH MITM.
 */

#include <proxy/ssh/sshmitm.hpp>

#include <cerrno>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <utility>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
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

char const* hostkey_policy_name(hostkey_policy policy) noexcept {
    switch (policy) {
        case hostkey_policy::insecure:   return "insecure";
        case hostkey_policy::accept_new: return "accept-new";
        case hostkey_policy::strict:     return "strict";
    }
    return "insecure";
}

hostkey_decision decide_hostkey(hostkey_policy policy, int known_state) noexcept {
    if (policy == hostkey_policy::insecure) return hostkey_decision::accept;
    if (known_state == SSH_KNOWN_HOSTS_OK) return hostkey_decision::accept;
    if (policy == hostkey_policy::accept_new
        && (known_state == SSH_KNOWN_HOSTS_UNKNOWN
            || known_state == SSH_KNOWN_HOSTS_NOT_FOUND)) {
        return hostkey_decision::learn;
    }
    return hostkey_decision::reject;
}

std::mutex& trusted_hostkeys_mutex() {
    static std::mutex instance;
    return instance;
}

channel_request_kind classify_channel_request(int subtype) noexcept {
    switch (subtype) {
        case SSH_CHANNEL_REQUEST_PTY:           return channel_request_kind::pty;
        case SSH_CHANNEL_REQUEST_SHELL:         return channel_request_kind::shell;
        case SSH_CHANNEL_REQUEST_EXEC:          return channel_request_kind::exec;
        case SSH_CHANNEL_REQUEST_SUBSYSTEM:     return channel_request_kind::subsystem;
        case SSH_CHANNEL_REQUEST_ENV:           return channel_request_kind::environment;
        case SSH_CHANNEL_REQUEST_WINDOW_CHANGE: return channel_request_kind::window_change;
        case SSH_CHANNEL_REQUEST_X11:           return channel_request_kind::x11;
        default:                                return channel_request_kind::unsupported;
    }
}

char const* channel_request_name(channel_request_kind kind) noexcept {
    switch (kind) {
        case channel_request_kind::pty:           return "pty";
        case channel_request_kind::shell:         return "shell";
        case channel_request_kind::exec:          return "exec";
        case channel_request_kind::subsystem:     return "subsystem";
        case channel_request_kind::environment:   return "environment";
        case channel_request_kind::window_change: return "window-change";
        case channel_request_kind::x11:           return "x11";
        case channel_request_kind::unsupported:   return "unsupported";
    }
    return "unsupported";
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
    enum class channel_mode { none, shell, exec };
    struct channel_pair {
        impl* owner = nullptr;
        ssh_channel downstream = nullptr;
        ssh_channel upstream = nullptr;
        int type = SSH_CHANNEL_UNKNOWN;
        std::string to_upstream;
        std::string to_downstream;
        std::string stderr_to_downstream;
        bool downstream_eof_forwarded = false;
        bool upstream_eof_forwarded = false;
        bool upstream_exit_forwarded = false;
        bool closing = false;
        channel_mode mode = channel_mode::none;
        ssh_channel_callbacks_struct downstream_callbacks{};
        bool agent_request_pending = false;
        bool agent_request_forwarded = false;
        bool expects_exit_state = false;
        std::string destination_address;
        int destination_port = 0;
        std::string originator_address;
        int originator_port = 0;

        ~channel_pair() {
            if (downstream) ssh_channel_free(downstream);
            if (upstream) ssh_channel_free(upstream);
        }
    };

    static void receive_agent_request(ssh_session, ssh_channel, void* userdata) {
        auto& channel = *static_cast<channel_pair*>(userdata);
        if (!channel.owner) return;
        if (channel.owner->options_.features.agent) {
            channel.agent_request_pending = true;
            channel.owner->emit_event(true,
                "ssh event=channel-request type=auth-agent action=pass");
        } else {
            channel.owner->emit_event(true,
                "ssh event=channel-request type=auth-agent action=reject");
        }
    }

    static ssh_channel accept_forwarded_tcpip(
            ssh_session session, char const* destination_address, int destination_port,
            char const* originator_address, int originator_port, void* userdata) {
        auto& self = *static_cast<impl*>(userdata);
        if (!self.options_.features.remote_forward) return nullptr;
        return self.queue_server_channel(session, SSH_CHANNEL_FORWARDED_TCPIP,
            destination_address, destination_port, originator_address, originator_port);
    }

    static ssh_channel accept_x11(ssh_session session, char const* originator_address,
                                  int originator_port, void* userdata) {
        auto& self = *static_cast<impl*>(userdata);
        if (!self.options_.features.x11) return nullptr;
        return self.queue_server_channel(session, SSH_CHANNEL_X11, "", 0,
                                         originator_address, originator_port);
    }

    static ssh_channel accept_agent(ssh_session session, void* userdata) {
        auto& self = *static_cast<impl*>(userdata);
        if (!self.options_.features.agent) return nullptr;
        return self.queue_server_channel(session, SSH_CHANNEL_AUTH_AGENT, "", 0, "", 0);
    }

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
        if (pending_global_message_) {
            ssh_message_free(pending_global_message_);
        }
        if (pending_open_message_) {
            ssh_message_free(pending_open_message_);
        }
        channels_.clear();
        retired_channels_.clear();
        server_open_channels_.clear();
        opening_channel_.reset();
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
        if (ssh_options_set(upstream_, SSH_OPTIONS_PORT,
                            &options_.upstream_port) != SSH_OK) {
            set_error(libssh_error(upstream_, "cannot set upstream SSH port"));
            return false;
        }
        if (options_.hostkeys != hostkey_policy::insecure
            && ssh_options_set(upstream_, SSH_OPTIONS_KNOWNHOSTS,
                               options_.trusted_hostkeys.c_str()) != SSH_OK) {
            set_error(libssh_error(upstream_, "cannot configure SSH trusted host keys"));
            return false;
        }
        if (ssh_options_set(upstream_, SSH_OPTIONS_FD, &upstream_fd_) != SSH_OK) {
            set_error(libssh_error(upstream_, "cannot attach upstream SSH socket"));
            return false;
        }

        ssh_set_blocking(upstream_, 0);
        ssh_set_blocking(downstream_, 0);
        ssh_callbacks_init(&upstream_callbacks_);
        upstream_callbacks_.userdata = this;
        upstream_callbacks_.channel_open_request_forwarded_tcpip_function =
            &impl::accept_forwarded_tcpip;
        upstream_callbacks_.channel_open_request_x11_function = &impl::accept_x11;
        upstream_callbacks_.channel_open_request_auth_agent_function = &impl::accept_agent;
        if (ssh_set_callbacks(upstream_, &upstream_callbacks_) != SSH_OK) {
            set_error(libssh_error(upstream_, "cannot install upstream SSH callbacks"));
            return false;
        }
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

    static char const* known_host_state_name(int state) noexcept {
        switch (state) {
            case SSH_KNOWN_HOSTS_ERROR:     return "error";
            case SSH_KNOWN_HOSTS_NOT_FOUND: return "not-found";
            case SSH_KNOWN_HOSTS_UNKNOWN:   return "unknown";
            case SSH_KNOWN_HOSTS_OK:        return "match";
            case SSH_KNOWN_HOSTS_CHANGED:   return "changed";
            case SSH_KNOWN_HOSTS_OTHER:     return "other-key-type";
        }
        return "invalid";
    }

    bool verify_upstream_hostkey() {
        if (options_.hostkeys == hostkey_policy::insecure) {
            xwar(transport_log())("upstream SSH host key verification disabled for %s:%u",
                                  options_.upstream_host.c_str(), options_.upstream_port);
            emit_event(false,
                "ssh event=hostkey policy=insecure action=accept verification=disabled");
            return true;
        }

        auto const lock = std::scoped_lock(trusted_hostkeys_mutex());
        auto const state = ssh_session_is_known_server(upstream_);
        auto const decision = decide_hostkey(options_.hostkeys, state);
        if (decision == hostkey_decision::learn) {
            std::error_code filesystem_error;
            auto const trusted_keys = std::filesystem::path(options_.trusted_hostkeys);
            std::filesystem::create_directories(trusted_keys.parent_path(), filesystem_error);
            if (filesystem_error) {
                set_error("cannot create SSH trusted-key directory: " + filesystem_error.message());
                return false;
            }
            if (ssh_session_update_known_hosts(upstream_) != SSH_OK) {
                auto const operation =
                    "cannot save upstream SSH host key to " + options_.trusted_hostkeys;
                set_error(libssh_error(upstream_, operation.c_str()));
                emit_event(false, string_format(
                    "ssh event=hostkey policy=%s state=%s action=error store=\"%s\"",
                    hostkey_policy_name(options_.hostkeys), known_host_state_name(state),
                    ESC_(options_.trusted_hostkeys).c_str()));
                return false;
            }
            if (::chmod(options_.trusted_hostkeys.c_str(), S_IRUSR | S_IWUSR) != 0) {
                set_error("cannot secure SSH trusted-key file: " + std::string(std::strerror(errno)));
                return false;
            }
            emit_event(false, string_format(
                "ssh event=hostkey policy=accept-new state=%s action=learn store=\"%s\"",
                known_host_state_name(state), ESC_(options_.trusted_hostkeys).c_str()));
            xdia(transport_log())("learned upstream SSH host key for %s:%u in %s",
                                  options_.upstream_host.c_str(), options_.upstream_port,
                                  options_.trusted_hostkeys.c_str());
            return true;
        }
        if (decision == hostkey_decision::reject) {
            emit_event(false, string_format(
                "ssh event=hostkey policy=%s state=%s action=reject store=\"%s\"",
                hostkey_policy_name(options_.hostkeys), known_host_state_name(state),
                ESC_(options_.trusted_hostkeys).c_str()));
            set_error(string_format(
                "upstream SSH host key rejected by %s policy: %s",
                hostkey_policy_name(options_.hostkeys), known_host_state_name(state)));
            return false;
        }

        emit_event(false, string_format(
            "ssh event=hostkey policy=%s state=match action=accept",
            hostkey_policy_name(options_.hostkeys)));
        return true;
    }

    drive_result drive_key_exchange() {
        if (!initialized_ && !initialize_sessions()) {
            return drive_result::failed;
        }

        if (!upstream_kex_done_) {
            auto const result = ssh_connect(upstream_);
            if (result == SSH_OK) {
                if (!verify_upstream_hostkey()) return drive_result::failed;
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
                authenticated_username_ = pending_username_;
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

    ssh_channel queue_server_channel(
            ssh_session session, int type, char const* destination_address,
            int destination_port, char const* originator_address, int originator_port) {
        auto channel = std::make_unique<channel_pair>();
        channel->upstream = ssh_channel_new(session);
        if (!channel->upstream) return nullptr;
        ssh_channel_set_blocking(channel->upstream, 0);
        channel->type = type;
        channel->destination_address = destination_address ? destination_address : "";
        channel->destination_port = destination_port;
        channel->originator_address = originator_address ? originator_address : "";
        channel->originator_port = originator_port;
        auto* accepted = channel->upstream;
        server_open_channels_.push_back(std::move(channel));
        return accepted;
    }

    drive_result drive_server_channel_open() {
        if (server_open_channels_.empty()) return drive_result::again;
        auto& channel = *server_open_channels_.front();
        if (!channel.downstream) {
            channel.downstream = ssh_channel_new(downstream_);
            if (!channel.downstream) {
                set_error(libssh_error(downstream_, "cannot allocate downstream SSH channel"));
                return drive_result::failed;
            }
            ssh_channel_set_blocking(channel.downstream, 0);
        }

        int result = SSH_ERROR;
        char const* type_name = "unknown";
        if (channel.type == SSH_CHANNEL_FORWARDED_TCPIP) {
            type_name = "forwarded-tcpip";
            result = ssh_channel_open_reverse_forward(
                channel.downstream, channel.destination_address.c_str(),
                channel.destination_port, channel.originator_address.c_str(),
                channel.originator_port);
        } else if (channel.type == SSH_CHANNEL_X11) {
            type_name = "x11";
            result = ssh_channel_open_x11(channel.downstream,
                                          channel.originator_address.c_str(),
                                          channel.originator_port);
        } else if (channel.type == SSH_CHANNEL_AUTH_AGENT) {
            type_name = "auth-agent";
            result = ssh_channel_open_auth_agent(channel.downstream);
        }
        if (result == SSH_AGAIN) return drive_result::again;
        if (result != SSH_OK) {
            set_error(libssh_error(downstream_, "cannot open downstream SSH relay channel"));
            return drive_result::failed;
        }

        emit_event(false, string_format("ssh event=channel-open type=%s action=pass",
                                        type_name));
        channels_.push_back(std::move(server_open_channels_.front()));
        server_open_channels_.erase(server_open_channels_.begin());
        return drive_result::progress;
    }

    drive_result drive_channel_open(ssh_message supplied_message = nullptr) {
        if (!pending_open_message_) {
            auto* message = supplied_message ? supplied_message : ssh_message_get(downstream_);
            if (!message) return drive_result::again;

            if (ssh_message_type(message) != SSH_REQUEST_CHANNEL_OPEN) {
                return reject_message(message, false);
            }

            auto const type = ssh_message_subtype(message);
            if(type != SSH_CHANNEL_SESSION && type != SSH_CHANNEL_DIRECT_TCPIP) {
                return reject_message(message, false);
            }
            if(type == SSH_CHANNEL_DIRECT_TCPIP && !options_.features.local_forward) {
                xdia(transport_log())("rejecting local TCP forwarding by SSH profile");
                emit_event(true, "ssh event=channel-open type=direct-tcpip action=reject");
                return reject_message(message, false);
            }

            opening_channel_ = std::make_unique<channel_pair>();
            opening_channel_->owner = this;
            opening_channel_->upstream = ssh_channel_new(upstream_);
            if (!opening_channel_->upstream) {
                set_error(libssh_error(upstream_, "cannot allocate upstream SSH channel"));
                ssh_message_free(message);
                opening_channel_.reset();
                return drive_result::failed;
            }
            ssh_channel_set_blocking(opening_channel_->upstream, 0);
            pending_open_message_ = message;
            opening_channel_->type = type;
        }

        int result = SSH_ERROR;
        if(opening_channel_->type == SSH_CHANNEL_SESSION) {
            result = ssh_channel_open_session(opening_channel_->upstream);
        } else if(opening_channel_->type == SSH_CHANNEL_DIRECT_TCPIP) {
            auto const* destination = ssh_message_channel_request_open_destination(
                pending_open_message_);
            auto const* originator = ssh_message_channel_request_open_originator(
                pending_open_message_);
            result = destination && originator
                ? ssh_channel_open_forward(
                    opening_channel_->upstream, destination,
                    ssh_message_channel_request_open_destination_port(pending_open_message_),
                    originator,
                    ssh_message_channel_request_open_originator_port(pending_open_message_))
                : SSH_ERROR;
        }
        if (result == SSH_AGAIN) return drive_result::again;
        if (result != SSH_OK) {
            auto* message = std::exchange(pending_open_message_, nullptr);
            reject_message(message, false);
            opening_channel_.reset();
            set_error(libssh_error(upstream_, "cannot open upstream SSH session channel"));
            return drive_result::failed;
        }

        auto* message = std::exchange(pending_open_message_, nullptr);
        opening_channel_->downstream = ssh_message_channel_request_open_reply_accept(message);
        ssh_message_free(message);
        if (!opening_channel_->downstream) {
            set_error(libssh_error(downstream_, "cannot accept downstream SSH session channel"));
            opening_channel_.reset();
            return drive_result::failed;
        }
        ssh_channel_set_blocking(opening_channel_->downstream, 0);
        if (opening_channel_->type == SSH_CHANNEL_SESSION) {
            ssh_callbacks_init(&opening_channel_->downstream_callbacks);
            opening_channel_->downstream_callbacks.userdata = opening_channel_.get();
            opening_channel_->downstream_callbacks.channel_auth_agent_req_function =
                &impl::receive_agent_request;
            if (ssh_set_channel_callbacks(
                    opening_channel_->downstream,
                    &opening_channel_->downstream_callbacks) != SSH_OK) {
                set_error(libssh_error(downstream_,
                    "cannot install downstream SSH channel callbacks"));
                opening_channel_.reset();
                return drive_result::failed;
            }
        }
        xdia(transport_log())("%s channel opened on both SSH legs",
                              opening_channel_->type == SSH_CHANNEL_SESSION
                                  ? "session" : "direct-tcpip");
        emit_event(true, string_format("ssh event=channel-open type=%s action=pass",
                   opening_channel_->type == SSH_CHANNEL_SESSION ? "session" : "direct-tcpip"));
        channels_.push_back(std::move(opening_channel_));
        return drive_result::progress;
    }

    bool feature_allowed(channel_request_kind kind) const {
        switch(kind) {
            case channel_request_kind::shell:         return options_.features.shell;
            case channel_request_kind::exec:          return options_.features.exec;
            case channel_request_kind::subsystem:     return options_.features.subsystem;
            case channel_request_kind::pty:           return options_.features.pty;
            case channel_request_kind::environment:   return options_.features.environment;
            case channel_request_kind::x11:           return options_.features.x11;
            case channel_request_kind::window_change: return options_.features.pty;
            case channel_request_kind::unsupported:   return false;
        }
        return false;
    }

    drive_result drive_global_request(ssh_message supplied_message = nullptr) {
        if (!pending_global_message_) {
            auto* message = supplied_message ? supplied_message : ssh_message_get(downstream_);
            if (!message) return drive_result::again;
            if (ssh_message_type(message) != SSH_REQUEST_GLOBAL) {
                return reject_message(message, false);
            }
            auto const subtype = ssh_message_subtype(message);
            if (!options_.features.remote_forward
                || (subtype != SSH_GLOBAL_REQUEST_TCPIP_FORWARD
                    && subtype != SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD)) {
                xdia(transport_log())("rejecting SSH global request subtype=%d by profile/support",
                                      subtype);
                emit_event(true, string_format(
                    "ssh event=remote-forward action=reject subtype=%d", subtype));
                return reject_message(message, false);
            }
            auto const* address = ssh_message_global_request_address(message);
            if (!address) return reject_message(message, false);
            pending_global_address_ = address;
            pending_global_port_ = ssh_message_global_request_port(message);
            pending_global_subtype_ = subtype;
            pending_global_message_ = message;
        }

        int bound_port = pending_global_port_;
        auto const result = pending_global_subtype_ == SSH_GLOBAL_REQUEST_TCPIP_FORWARD
            ? ssh_channel_listen_forward(upstream_, pending_global_address_.c_str(),
                                         pending_global_port_, &bound_port)
            : ssh_channel_cancel_forward(upstream_, pending_global_address_.c_str(),
                                         pending_global_port_);
        if (result == SSH_AGAIN) return drive_result::again;

        auto* message = std::exchange(pending_global_message_, nullptr);
        if (result != SSH_OK) {
            pending_global_address_.clear();
            return reject_message(message, false);
        }
        auto const action = pending_global_subtype_ == SSH_GLOBAL_REQUEST_TCPIP_FORWARD
            ? "listen" : "cancel";
        if (ssh_message_global_request_reply_success(
                message, static_cast<std::uint16_t>(bound_port)) != SSH_OK) {
            ssh_message_free(message);
            set_error(libssh_error(downstream_, "cannot confirm downstream global request"));
            return drive_result::failed;
        }
        emit_event(true, string_format(
            "ssh event=remote-forward action=%s address=\"%s\" port=%d bound_port=%d",
            action, ESC_(pending_global_address_).c_str(), pending_global_port_, bound_port));
        ssh_message_free(message);
        pending_global_address_.clear();
        return drive_result::progress;
    }

    int forward_channel_request(channel_pair& channel, ssh_message message) {
        switch (classify_channel_request(ssh_message_subtype(message))) {
            case channel_request_kind::pty: {
                auto const request = message_pty_request(message);
                return ssh_channel_request_pty_size(channel.upstream, request.terminal.c_str(),
                                                    request.columns, request.rows);
            }
            case channel_request_kind::shell:
                return ssh_channel_request_shell(channel.upstream);
            case channel_request_kind::exec: {
                auto const* command = ssh_message_channel_request_command(message);
                return command ? ssh_channel_request_exec(channel.upstream, command) : SSH_ERROR;
            }
            case channel_request_kind::subsystem: {
                auto const* subsystem = ssh_message_channel_request_subsystem(message);
                return subsystem ? ssh_channel_request_subsystem(channel.upstream, subsystem) : SSH_ERROR;
            }
            case channel_request_kind::environment: {
                auto const* name = ssh_message_channel_request_env_name(message);
                auto const* value = ssh_message_channel_request_env_value(message);
                return name && value ? ssh_channel_request_env(channel.upstream, name, value) : SSH_ERROR;
            }
            case channel_request_kind::window_change: {
                auto const request = message_pty_request(message);
                return ssh_channel_change_pty_size(channel.upstream, request.columns, request.rows);
            }
            case channel_request_kind::x11: {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
                auto const single = ssh_message_channel_request_x11_single_connection(message);
                auto const* protocol = ssh_message_channel_request_x11_auth_protocol(message);
                auto const* cookie = ssh_message_channel_request_x11_auth_cookie(message);
                auto const screen = ssh_message_channel_request_x11_screen_number(message);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
                return protocol && cookie
                    ? ssh_channel_request_x11(channel.upstream, single, protocol, cookie, screen)
                    : SSH_ERROR;
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

            if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN) {
                return drive_channel_open(message);
            }
            if (ssh_message_type(message) == SSH_REQUEST_GLOBAL) {
                return drive_global_request(message);
            }
            auto const kind = classify_channel_request(ssh_message_subtype(message));
            auto* requested = ssh_message_type(message) == SSH_REQUEST_CHANNEL
                ? ssh_message_channel_request_channel(message) : nullptr;
            auto const found = std::find_if(channels_.begin(), channels_.end(),
                [requested](auto const& pair) { return pair->downstream == requested; });
            if (found == channels_.end() || (*found)->type != SSH_CHANNEL_SESSION
                || !feature_allowed(kind)) {
                xdia(transport_log())("rejecting SSH channel request subtype=%d by profile/support",
                                      ssh_message_subtype(message));
                emit_event(true, string_format(
                    "ssh event=channel-request type=%s subtype=%d action=reject",
                    channel_request_name(kind), ssh_message_subtype(message)));
                return reject_message(message, false);
            }
            pending_request_channel_ = found->get();
            pending_channel_message_ = message;
        }

        auto const result = forward_channel_request(*pending_request_channel_,
                                                    pending_channel_message_);
        if (result == SSH_AGAIN) return drive_result::again;

        auto* message = std::exchange(pending_channel_message_, nullptr);
        auto* channel = std::exchange(pending_request_channel_, nullptr);
        if (result == SSH_OK) {
            auto const kind = classify_channel_request(ssh_message_subtype(message));
            if (kind == channel_request_kind::shell) {
                channel->mode = channel_mode::shell;
                channel->expects_exit_state = true;
                xdia(transport_log())("interactive shell requested");
                emit_event(true, "ssh event=shell action=pass");
            } else if (kind == channel_request_kind::exec) {
                channel->mode = channel_mode::exec;
                channel->expects_exit_state = true;
                auto const* command = ssh_message_channel_request_command(message);
                xdeb(exec_log())("request command='%s'", command ? command : "");
                emit_event(true, string_format("ssh event=exec command=\"%s\" action=pass",
                                               command ? ESC_(command).c_str() : ""));
            } else if (kind == channel_request_kind::subsystem) {
                channel->mode = channel_mode::exec;
                channel->expects_exit_state = true;
                auto const* subsystem = ssh_message_channel_request_subsystem(message);
                xdeb(exec_log())("request subsystem='%s'", subsystem ? subsystem : "");
                emit_event(true, string_format("ssh event=subsystem name=\"%s\" action=pass",
                                               subsystem ? ESC_(subsystem).c_str() : ""));
            } else if (kind == channel_request_kind::environment) {
                auto const* name = ssh_message_channel_request_env_name(message);
                auto const* value = ssh_message_channel_request_env_value(message);
                xdeb(transport_log())("environment %s='%s'", name ? name : "", value ? value : "");
                emit_event(true, string_format(
                    "ssh event=environment name=\"%s\" value=\"%s\" action=pass",
                    name ? ESC_(name).c_str() : "", value ? ESC_(value).c_str() : ""));
            } else if (kind == channel_request_kind::pty) {
                auto const request = message_pty_request(message);
                xdeb(transport_log())("pty term='%s' size=%dx%d", request.terminal.c_str(),
                                      request.columns, request.rows);
                emit_event(true, string_format(
                    "ssh event=pty term=\"%s\" columns=%d rows=%d action=pass",
                    ESC_(request.terminal).c_str(), request.columns, request.rows));
            } else if (kind == channel_request_kind::window_change) {
                auto const request = message_pty_request(message);
                xdeb(transport_log())("pty resize=%dx%d", request.columns, request.rows);
                emit_event(true, string_format(
                    "ssh event=window-change columns=%d rows=%d action=pass",
                    request.columns, request.rows));
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
                     bool upstream_direction, channel_mode mode) {
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
            emit_event(upstream_direction,
                       string_format("ssh event=relay direction=%s bytes=%d",
                                     upstream_direction ? "up" : "down", amount));
            auto* payload_log = mode == channel_mode::shell
                ? &shell_log()
                : mode == channel_mode::exec ? &exec_log() : nullptr;
            if (payload_log && *payload_log->level() >= DEB) {
                payload_log->deb("%s%s %dB: %s", direction,
                                 stderr_stream ? " stderr" : "",
                                 amount, printable(pending).c_str());
            }
        }
        return amount;
    }

    drive_result drive_channel_data(channel_pair& channel) {
        bool progress = false;
        if (channel.closing) {
            if (!ssh_channel_is_closed(channel.upstream)) {
                auto const result = ssh_channel_close(channel.upstream);
                if (result == SSH_ERROR) {
                    set_error("cannot close upstream SSH channel");
                    return drive_result::failed;
                }
                progress = progress || result == SSH_OK;
            }
            if (!ssh_channel_is_closed(channel.downstream)) {
                auto const result = ssh_channel_close(channel.downstream);
                if (result == SSH_ERROR) {
                    set_error("cannot close downstream SSH channel");
                    return drive_result::failed;
                }
                progress = progress || result == SSH_OK;
            }
            return progress ? drive_result::progress : drive_result::again;
        }

        // Exit status/signal is channel metadata, not payload. A fast peer may
        // mark the channel closed in the same dispatch that delivers it, so
        // collect and forward the metadata before the generic closed-channel
        // path below can retire the pair.
        if (channel.expects_exit_state && !channel.upstream_exit_forwarded) {
            std::uint32_t exit_code = 0;
            char* exit_signal = nullptr;
            int core_dumped = 0;
            auto const result = ssh_channel_get_exit_state(
                channel.upstream, &exit_code, &exit_signal, &core_dumped);
            if (result == SSH_OK) {
                int forward_result;
                if (exit_signal) {
                    forward_result = ssh_channel_request_send_exit_signal(
                        channel.downstream, exit_signal, core_dumped, "", "");
                } else {
                    forward_result = ssh_channel_request_send_exit_status(
                        channel.downstream, static_cast<int>(exit_code));
                }
                std::free(exit_signal);
                if (forward_result != SSH_OK) {
                    set_error("cannot forward upstream SSH exit state");
                    return drive_result::failed;
                }
                channel.upstream_exit_forwarded = true;
                progress = true;
            } else {
                std::free(exit_signal);
                if (result != SSH_AGAIN) {
                    set_error(libssh_error(upstream_, "cannot read upstream SSH exit state"));
                    return drive_result::failed;
                }
            }
        }
        if ((ssh_channel_is_closed(channel.downstream)
             || ssh_channel_is_closed(channel.upstream))
            && channel.to_upstream.empty() && channel.to_downstream.empty()
            && channel.stderr_to_downstream.empty()
            && (!channel.expects_exit_state || channel.upstream_exit_forwarded)) {
            channel.closing = true;
            return drive_result::progress;
        }
        auto flush = [&progress](ssh_channel channel, std::string& pending,
                                 bool stderr_stream) {
            auto const result = flush_channel_buffer(channel, pending, stderr_stream);
            if (result == SSH_ERROR) {
                return false;
            }
            progress = progress || result > 0;
            return true;
        };
        if (!flush(channel.upstream, channel.to_upstream, false)
            || !flush(channel.downstream, channel.to_downstream, false)
            || (channel.type == SSH_CHANNEL_SESSION
                && !flush(channel.downstream, channel.stderr_to_downstream, true))) {
            set_error("SSH channel write failed");
            return drive_result::failed;
        }

        auto read = [this, &progress](ssh_channel channel, std::string& pending,
                                     bool stderr_stream, char const* direction,
                                     std::uint64_t& byte_counter, bool upstream_direction,
                                     channel_mode mode) {
            auto const result = read_channel(channel, pending, stderr_stream, direction,
                                             byte_counter, upstream_direction, mode);
            if (result == SSH_ERROR) {
                return false;
            }
            progress = progress || result > 0;
            return true;
        };
        // Stop immediately on error. Further libssh calls on the same failed
        // session can invalidate channel state needed by teardown.
        if (!read(channel.downstream, channel.to_upstream, false, "client->server", bytes_up_, true, channel.mode)
            || !read(channel.upstream, channel.to_downstream, false, "server->client", bytes_down_, false, channel.mode)
            || (channel.type == SSH_CHANNEL_SESSION
                && !read(channel.upstream, channel.stderr_to_downstream, true,
                         "server->client", bytes_down_, false, channel.mode))) {
            set_error("SSH channel read failed");
            return drive_result::failed;
        }

        if (ssh_channel_is_eof(channel.downstream) && !channel.downstream_eof_forwarded) {
            if (ssh_channel_send_eof(channel.upstream) == SSH_ERROR) {
                set_error("cannot forward downstream SSH EOF");
                return drive_result::failed;
            }
            channel.downstream_eof_forwarded = true;
            progress = true;
        }
        if (ssh_channel_is_eof(channel.upstream) && !channel.upstream_eof_forwarded
            && channel.to_downstream.empty() && channel.stderr_to_downstream.empty()) {
            if (ssh_channel_send_eof(channel.downstream) == SSH_ERROR) {
                set_error("cannot forward upstream SSH EOF");
                return drive_result::failed;
            }
            channel.upstream_eof_forwarded = true;
            progress = true;
        }

        auto const drained = channel.to_upstream.empty()
            && channel.to_downstream.empty() && channel.stderr_to_downstream.empty();
        auto const completion_forwarded = channel.upstream_eof_forwarded
            && (!channel.expects_exit_state || channel.upstream_exit_forwarded);
        if (drained && completion_forwarded) {
            channel.closing = true;
            progress = true;
        }

        return progress ? drive_result::progress : drive_result::again;
    }

    drive_result drive_agent_requests() {
        for (auto& channel : channels_) {
            if (!channel->agent_request_pending || channel->agent_request_forwarded) {
                continue;
            }
            auto const result = ssh_channel_request_auth_agent(channel->upstream);
            if (result == SSH_AGAIN) return drive_result::again;
            if (result == SSH_ERROR) {
                set_error(libssh_error(upstream_, "cannot forward SSH agent request"));
                return drive_result::failed;
            }
            channel->agent_request_pending = false;
            channel->agent_request_forwarded = true;
            return drive_result::progress;
        }
        return drive_result::finished;
    }

    drive_result drive_channels() {
        bool progress = false;

        auto const queued_before_callbacks = server_open_channels_.size();
        auto const callback_result = ssh_execute_message_callbacks(upstream_);
        if (callback_result == SSH_ERROR) {
            set_error(libssh_error(upstream_, "cannot process upstream SSH callbacks"));
            return drive_result::failed;
        }
        progress = server_open_channels_.size() != queued_before_callbacks;

        auto const agent_result = drive_agent_requests();
        if (agent_result == drive_result::failed) return agent_result;
        auto const control_request_pending = agent_result == drive_result::again;
        progress = progress || agent_result == drive_result::progress;

        if (control_request_pending) {
            // Keep relaying channel data below, but do not start another
            // upstream request/reply transaction on this session yet.
        } else if (!server_open_channels_.empty()) {
            auto const server_open_result = drive_server_channel_open();
            if (server_open_result == drive_result::failed) return server_open_result;
            progress = progress || server_open_result == drive_result::progress;
        } else if (pending_global_message_) {
            auto const global_result = drive_global_request();
            if (global_result == drive_result::failed) return global_result;
            progress = progress || global_result == drive_result::progress;
        } else if (pending_open_message_) {
            auto const open_result = drive_channel_open();
            if (open_result == drive_result::failed) return open_result;
            progress = progress || open_result == drive_result::progress;
        } else {
            auto const request_result = drive_channel_request();
            if (request_result == drive_result::failed) return request_result;
            progress = progress || request_result == drive_result::progress;
        }

        for (auto& channel : channels_) {
            auto const data_result = drive_channel_data(*channel);
            if (data_result == drive_result::failed) return data_result;
            progress = progress || data_result == drive_result::progress;
        }

        for (auto iterator = channels_.begin(); iterator != channels_.end();) {
            auto const& channel = *iterator;
            auto const drained = channel->to_upstream.empty()
                && channel->to_downstream.empty()
                && channel->stderr_to_downstream.empty();
            auto const closed = ssh_channel_is_closed(channel->upstream)
                && ssh_channel_is_closed(channel->downstream);
            if (drained && closed) {
                emit_event(false, "ssh event=channel-close");
                retired_channels_.push_back(std::move(*iterator));
                iterator = channels_.erase(iterator);
                progress = true;
            } else {
                ++iterator;
            }
        }

        if (!ssh_is_connected(downstream_) || !ssh_is_connected(upstream_)) {
            if (!fsm_.begin_closing()) {
                error_ = fsm_.error();
                return drive_result::failed;
            }
            return drive_result::progress;
        }
        return progress ? drive_result::progress : drive_result::again;
    }

    drive_result drive_closing() {
        for (auto& channel : channels_) {
            if (channel->upstream && !ssh_channel_is_closed(channel->upstream)) {
                auto const result = ssh_channel_close(channel->upstream);
                if (result == SSH_AGAIN) return drive_result::again;
            }
            if (channel->downstream && !ssh_channel_is_closed(channel->downstream)) {
                auto const result = ssh_channel_close(channel->downstream);
                if (result == SSH_AGAIN) return drive_result::again;
            }
        }
        if (!fsm_.close_complete()) {
            error_ = fsm_.error();
            return drive_result::failed;
        }
        xdia(transport_log())("SSH transport closed");
        return drive_result::finished;
    }

    void emit_event(bool upstream, std::string const& event) const {
        if(options_.event_observer) options_.event_observer(upstream, event);
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
    ssh_callbacks_struct upstream_callbacks_{};
    bool initialized_ = false;
    bool downstream_kex_done_ = false;
    bool upstream_kex_done_ = false;
    ssh_message pending_auth_message_ = nullptr;
    std::string pending_username_;
    std::string pending_password_;
    std::string authenticated_username_;
    ssh_message pending_open_message_ = nullptr;
    ssh_message pending_channel_message_ = nullptr;
    ssh_message pending_global_message_ = nullptr;
    std::string pending_global_address_;
    int pending_global_port_ = 0;
    int pending_global_subtype_ = SSH_GLOBAL_REQUEST_UNKNOWN;
    channel_pair* pending_request_channel_ = nullptr;
    std::unique_ptr<channel_pair> opening_channel_;
    std::vector<std::unique_ptr<channel_pair>> channels_;
    std::vector<std::unique_ptr<channel_pair>> server_open_channels_;
    // libssh may retain internal references while processing another channel
    // on the same session. Release closed channel handles at session teardown.
    std::vector<std::unique_ptr<channel_pair>> retired_channels_;
    std::uint64_t bytes_up_ = 0;
    std::uint64_t bytes_down_ = 0;

public:
    [[nodiscard]] std::string diagnostics() const {
        std::size_t session_channels = 0;
        std::size_t forwarding_channels = 0;
        for (auto const& channel : channels_) {
            if (channel->type == SSH_CHANNEL_SESSION) ++session_channels;
            else ++forwarding_channels;
        }
        std::stringstream out;
        out << "profile=" << (options_.profile_name.empty() ? "-" : options_.profile_name)
            << " hostkey_policy=" << hostkey_policy_name(options_.hostkeys)
            << " user=\"" << ESC_(authenticated_username_) << '"'
            << " client_banner=\"" << ESC_(fsm_.client_identification().raw) << '"'
            << " server_banner=\"" << ESC_(fsm_.server_identification().raw) << '"'
            << " channels=" << channels_.size()
            << " session=" << session_channels
            << " forwarding=" << forwarding_channels
            << " retired=" << retired_channels_.size()
            << " opening=" << (opening_channel_ ? 1 : 0)
            << " queued_server=" << server_open_channels_.size();
        if (!error_.empty()) out << " error=\"" << ESC_(error_) << '"';
        return out.str();
    }
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

std::string mitm_transport::diagnostics() const {
    return impl_->diagnostics();
}

} // namespace sx::ssh
