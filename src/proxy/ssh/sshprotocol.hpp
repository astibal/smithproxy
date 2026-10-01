/*
 * Smithproxy SSH MITM protocol helpers.
 */

#ifndef SMITHPROXY_SSHPROTOCOL_HPP
#define SMITHPROXY_SSHPROTOCOL_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace sx::ssh {

enum class protocol_version {
    unknown,
    ssh1,
    ssh2,
    unsupported,
};

struct identification {
    protocol_version version = protocol_version::unknown;
    std::string protocol;
    std::string software;
    std::string comments;

    // Exact identification line, without the terminating CRLF/LF. This is
    // retained so the downstream server leg can advertise the real upstream
    // server identification instead of a Smithproxy-generated value.
    std::string raw;
    std::vector<std::string> preamble;
};

enum class parse_status {
    need_more,
    complete,
    invalid,
};

class identification_parser {
public:
    explicit identification_parser(bool allow_preamble);

    parse_status feed(std::string_view bytes);

    [[nodiscard]] parse_status status() const noexcept { return status_; }
    [[nodiscard]] identification const& result() const noexcept { return result_; }
    [[nodiscard]] std::string const& error() const noexcept { return error_; }

private:
    parse_status parse_line(std::string line);
    parse_status fail(std::string reason);

    bool allow_preamble_;
    parse_status status_ = parse_status::need_more;
    std::string pending_;
    identification result_;
    std::string error_;
    std::size_t lines_seen_ = 0;
};

enum class mitm_state {
    detect,
    upstream_connect,
    server_identification,
    client_identification,
    key_exchange,
    authentication,
    channels,
    closing,
    closed,
    blocked,
    failed,
};

[[nodiscard]] bool transition_allowed(mitm_state from, mitm_state to) noexcept;
[[nodiscard]] char const* state_name(mitm_state state) noexcept;

class handshake_fsm {
public:
    [[nodiscard]] mitm_state state() const noexcept { return state_; }
    [[nodiscard]] std::string const& error() const noexcept { return error_; }
    [[nodiscard]] identification const& server_identification() const noexcept {
        return server_parser_.result();
    }
    [[nodiscard]] identification const& client_identification() const noexcept {
        return client_parser_.result();
    }

    bool begin_upstream_connect();
    bool upstream_connected();
    parse_status feed_server_identification(std::string_view bytes);
    parse_status feed_client_identification(std::string_view bytes);
    bool key_exchange_complete();
    void fail(std::string reason);

private:
    bool move_to(mitm_state next);
    parse_status handle_identification_result(
        identification_parser const& parser,
        parse_status status,
        mitm_state next);

    mitm_state state_ = mitm_state::detect;
    identification_parser server_parser_{true};
    identification_parser client_parser_{false};
    std::string error_;
};

} // namespace sx::ssh

#endif
