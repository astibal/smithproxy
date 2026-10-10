#include <proxy/httpconnect/httpconnect.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <sstream>

namespace {

constexpr std::size_t max_connect_header_size = 8 * 1024;

class HttpConnectFramingTCPCom final : public TCPCom {
public:
    // This transport exists only while parsing the CONNECT preface.  Child
    // connections are ordinary TCP transports.
    baseCom* replicate() override { return new TCPCom(); }

    ssize_t read(int fd, void* destination, std::size_t capacity,
                 int flags) override {
        if(header_complete_) {
            // baseHostCX drains a readable stream in a loop before it runs the
            // protocol handoff.  Do not let that same plaintext parser consume
            // tunnel bytes after the terminator; the replacement transport
            // will receive them on the next dispatch.
            errno = EAGAIN;
            return -1;
        }
        if(capacity == 0 || (flags & MSG_PEEK) != 0)
            return TCPCom::read(fd, destination, capacity, flags);

        std::array<unsigned char, max_connect_header_size> preview{};
        const auto preview_capacity = std::min(capacity, preview.size());
        const auto available = TCPCom::peek(
            fd, preview.data(), preview_capacity, flags);
        if(available <= 0)
            return available;

        auto match = delimiter_match_;
        std::size_t consume = static_cast<std::size_t>(available);
        for(std::size_t i = 0; i < consume; ++i) {
            match = advance_match(match, preview[i]);
            if(match == delimiter.size()) {
                consume = i + 1;
                break;
            }
        }

        const auto received = TCPCom::read(fd, destination, consume, flags);
        if(received > 0) {
            auto const* bytes = static_cast<unsigned char const*>(destination);
            for(ssize_t i = 0; i < received; ++i) {
                delimiter_match_ = advance_match(delimiter_match_, bytes[i]);
                if(delimiter_match_ == delimiter.size()) {
                    header_complete_ = true;
                    break;
                }
            }
        }
        return received;
    }

private:
    static constexpr std::array<unsigned char, 4> delimiter {
        '\r', '\n', '\r', '\n'
    };

    static std::size_t advance_match(std::size_t match,
                                     unsigned char byte) noexcept {
        if(byte == delimiter[match])
            return match + 1;
        return byte == delimiter[0] ? 1U : 0U;
    }

    std::size_t delimiter_match_ = 0;
    bool header_complete_ = false;
};

} // namespace

HttpConnectServerCX::HttpConnectServerCX(baseCom* c, unsigned int s)
    : ExplicitProxyCX(c, s) {
    // A zero return from process_in() means that the CONNECT headers are
    // incomplete. baseHostCX auto-finish would discard that partial input
    // before the next read, so retain it for incremental parsing.
    auto_finish(false);
}

void HttpConnectServerCX::send_error(unsigned int status, std::string_view reason) {
    auto const response = string_format(
            "HTTP/1.1 %u %.*s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            status, static_cast<int>(reason.size()), reason.data());
    writebuf()->append(response.data(), response.size());
    close_after_reply_ = true;
    state(explicit_state::REQRES_SENT);
    com()->set_write_monitor(socket());
}

std::size_t HttpConnectServerCX::process_in() {
    if(state_ != explicit_state::INIT) {
        return 0;
    }

    std::string_view const data(
            reinterpret_cast<char const*>(readbuf()->data()), readbuf()->size());
    auto const headers_end = data.find("\r\n\r\n");
    if(headers_end == std::string_view::npos) {
        if(data.size() >= max_connect_header_size) {
            send_error(431, "Request Header Fields Too Large");
            return data.size();
        }
        return 0;
    }

    auto const request_size = headers_end + 4;
    if(request_size >= max_connect_header_size) {
        send_error(431, "Request Header Fields Too Large");
        return request_size;
    }

    auto const line_end = data.find("\r\n");
    auto const request = HttpConnectRequest::parse(data.substr(0, line_end + 2));
    if(not request) {
        send_error(400, "Bad Request");
        return request_size;
    }

    // setup_target() can replace this frontend before process_in() returns.
    // Publish the exact framing boundary first so bytes pipelined after the
    // CONNECT headers survive that handoff.
    req_hdr_size = request_size;
    request_error_ = prepare_connect_target(request->host, request->port);
    if(request_error_ != explicit_request_error::NONE) {
        send_error(502, "Bad Gateway");
    }

    return request_size;
}

std::size_t HttpConnectServerCX::process_proxy_reply() {
    if(verdict_ == explicit_policy::ACCEPT) {
        // Unlike SOCKS, CONNECT must not report success before the upstream
        // TCP connection is established. ExplicitProxy sends the response
        // after the non-blocking connect completes.
        state(explicit_state::HANDOFF);
        com()->set_write_monitor(socket());
        return 0;
    } else {
        static constexpr std::string_view response =
                "HTTP/1.1 403 Forbidden\r\n"
                "Connection: close\r\nContent-Length: 0\r\n\r\n";
        writebuf()->append(response.data(), response.size());
        close_after_reply_ = true;
    }

    state(explicit_state::REQRES_SENT);
    com()->set_write_monitor(socket());
    return writebuf()->size();
}

std::string_view HttpConnectServerCX::upstream_success_response() const {
    return "HTTP/1.1 200 Connection Established\r\n"
           "Proxy-Agent: smithproxy\r\n\r\n";
}

std::string_view HttpConnectServerCX::upstream_failure_response() const {
    return "HTTP/1.1 502 Bad Gateway\r\n"
           "Connection: close\r\nContent-Length: 0\r\n\r\n";
}

void HttpConnectServerCX::pre_write() {
    if(close_after_reply_) {
        if(writebuf()->empty()) {
            error(true);
        }
        return;
    }
    ExplicitProxyCX::pre_write();
}

std::string HttpConnectProxy::to_string(int lev) const {
    std::stringstream result;
    if(lev >= iINF) {
        result << "HttpConnect|";
    }
    result << MitmProxy::to_string(lev);
    return result.str();
}

void HttpConnectProxy::on_left_message(baseHostCX* basecx) {
    if(auto* cx = dynamic_cast<HttpConnectServerCX*>(basecx); cx != nullptr) {
        handle_explicit_connect(cx);
    }
}

baseHostCX* MitmHttpConnectProxy::new_cx(int s) {
    auto* transport = new HttpConnectFramingTCPCom();
    transport->master(com()->master());
    return new HttpConnectServerCX(transport, s);
}

void MitmHttpConnectProxy::on_left_new(std::unique_ptr<baseHostCX> accepted_cx) {
    if(not accepted_cx) return;

    auto proxy = std::make_unique<HttpConnectProxy>(com()->slave());
    accepted_cx->name();
    proxy->ladd(accepted_cx.get());
    accepted_cx.release();
    add_proxy(std::move(proxy));
}
