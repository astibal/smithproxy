/*
 * Smithproxy SSH MITM protocol helpers.
 */

#include <proxy/ssh/sshprotocol.hpp>

#include <algorithm>
#include <utility>

namespace sx::ssh {

namespace {

constexpr std::size_t max_identification_line = 255;
constexpr std::size_t max_preamble_lines = 50;
constexpr std::size_t max_preamble_bytes = 8192;

bool has_control_character(std::string const& value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char c) {
        return c < 0x20 || c == 0x7f;
    });
}

} // namespace

identification_parser::identification_parser(bool allow_preamble)
    : allow_preamble_(allow_preamble) {}

parse_status identification_parser::fail(std::string reason) {
    error_ = std::move(reason);
    status_ = parse_status::invalid;
    return status_;
}

parse_status identification_parser::feed(std::string_view bytes) {
    if (status_ != parse_status::need_more) {
        return status_;
    }

    pending_.append(bytes.data(), bytes.size());
    if (pending_.size() > max_preamble_bytes) {
        return fail("SSH identification preamble is too large");
    }

    while (true) {
        auto const newline = pending_.find('\n');
        if (newline == std::string::npos) {
            if (pending_.size() > max_identification_line && result_.preamble.empty()) {
                return fail("SSH identification line exceeds 255 bytes");
            }
            return parse_status::need_more;
        }

        auto line = pending_.substr(0, newline);
        pending_.erase(0, newline + 1);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.rfind("SSH-", 0) == 0) {
            if (line.size() + 2 > max_identification_line) {
                return fail("SSH identification line exceeds 255 bytes");
            }
            return parse_line(std::move(line));
        }

        if (!allow_preamble_) {
            return fail("SSH client sent data before its identification line");
        }
        if (++lines_seen_ > max_preamble_lines) {
            return fail("too many lines before SSH identification");
        }
        result_.preamble.push_back(std::move(line));
    }
}

parse_status identification_parser::parse_line(std::string line) {
    // RFC 4253: SSH-protoversion-softwareversion SP comments CR LF
    auto const protocol_end = line.find('-', 4);
    if (protocol_end == std::string::npos || protocol_end == 4) {
        return fail("malformed SSH protocol version");
    }

    auto const software_end = line.find(' ', protocol_end + 1);
    auto const software_length = (software_end == std::string::npos)
        ? std::string::npos
        : software_end - protocol_end - 1;

    result_.raw = line;
    result_.protocol = line.substr(4, protocol_end - 4);
    result_.software = line.substr(protocol_end + 1, software_length);
    if (software_end != std::string::npos) {
        result_.comments = line.substr(software_end + 1);
    }

    if (result_.software.empty() || has_control_character(result_.raw)) {
        return fail("malformed SSH software version");
    }

    if (result_.protocol == "2.0" || result_.protocol == "1.99") {
        result_.version = protocol_version::ssh2;
    } else if (result_.protocol.rfind("1.", 0) == 0) {
        result_.version = protocol_version::ssh1;
    } else {
        result_.version = protocol_version::unsupported;
    }

    status_ = parse_status::complete;
    return status_;
}

bool transition_allowed(mitm_state from, mitm_state to) noexcept {
    if (to == mitm_state::failed || to == mitm_state::blocked) {
        return from != mitm_state::closed;
    }
    if (to == mitm_state::closing) {
        return from != mitm_state::closed && from != mitm_state::blocked && from != mitm_state::failed;
    }

    switch (from) {
        case mitm_state::detect:                return to == mitm_state::upstream_connect;
        case mitm_state::upstream_connect:      return to == mitm_state::server_identification;
        case mitm_state::server_identification: return to == mitm_state::client_identification;
        case mitm_state::client_identification: return to == mitm_state::key_exchange;
        case mitm_state::key_exchange:          return to == mitm_state::authentication;
        case mitm_state::authentication:        return to == mitm_state::channels;
        case mitm_state::channels:              return false;
        case mitm_state::closing:               return to == mitm_state::closed;
        case mitm_state::blocked:               return to == mitm_state::closed;
        case mitm_state::failed:                return to == mitm_state::closed;
        case mitm_state::closed:                return false;
    }
    return false;
}

char const* state_name(mitm_state state) noexcept {
    switch (state) {
        case mitm_state::detect:                return "detect";
        case mitm_state::upstream_connect:      return "upstream-connect";
        case mitm_state::server_identification: return "server-identification";
        case mitm_state::client_identification: return "client-identification";
        case mitm_state::key_exchange:          return "key-exchange";
        case mitm_state::authentication:        return "authentication";
        case mitm_state::channels:              return "channels";
        case mitm_state::closing:               return "closing";
        case mitm_state::closed:                return "closed";
        case mitm_state::blocked:               return "blocked";
        case mitm_state::failed:                return "failed";
    }
    return "unknown";
}

bool handshake_fsm::move_to(mitm_state next) {
    if (!transition_allowed(state_, next)) {
        error_ = std::string("invalid SSH MITM transition from ")
            + state_name(state_) + " to " + state_name(next);
        state_ = mitm_state::failed;
        return false;
    }
    state_ = next;
    return true;
}

bool handshake_fsm::begin_upstream_connect() {
    return move_to(mitm_state::upstream_connect);
}

bool handshake_fsm::upstream_connected() {
    return move_to(mitm_state::server_identification);
}

parse_status handshake_fsm::handle_identification_result(
        identification_parser const& parser,
        parse_status status,
        mitm_state next) {
    if (status == parse_status::need_more) {
        return status;
    }
    if (status == parse_status::invalid) {
        error_ = parser.error();
        state_ = mitm_state::failed;
        return status;
    }
    if (parser.result().version == protocol_version::ssh1) {
        error_ = "SSH protocol version 1 is blocked";
        state_ = mitm_state::blocked;
        return status;
    }
    if (parser.result().version != protocol_version::ssh2) {
        error_ = "unsupported SSH protocol version: " + parser.result().protocol;
        state_ = mitm_state::blocked;
        return status;
    }
    move_to(next);
    return status;
}

parse_status handshake_fsm::feed_server_identification(std::string_view bytes) {
    if (state_ != mitm_state::server_identification) {
        fail("server identification received in the wrong state");
        return parse_status::invalid;
    }
    auto const status = server_parser_.feed(bytes);
    return handle_identification_result(
        server_parser_, status, mitm_state::client_identification);
}

parse_status handshake_fsm::feed_client_identification(std::string_view bytes) {
    if (state_ != mitm_state::client_identification) {
        fail("client identification received in the wrong state");
        return parse_status::invalid;
    }
    auto const status = client_parser_.feed(bytes);
    return handle_identification_result(
        client_parser_, status, mitm_state::key_exchange);
}

bool handshake_fsm::key_exchange_complete() {
    return move_to(mitm_state::authentication);
}

void handshake_fsm::fail(std::string reason) {
    error_ = std::move(reason);
    if (state_ != mitm_state::closed) {
        state_ = mitm_state::failed;
    }
}

} // namespace sx::ssh
