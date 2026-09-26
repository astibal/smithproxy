#include <proxy/httpconnect/httpconnect.hpp>

#include <sstream>

namespace {

constexpr std::size_t max_connect_header_size = 16 * 1024;

} // namespace

void HttpConnectServerCX::send_error(unsigned int status, std::string_view reason) {
    auto const response = string_format(
            "HTTP/1.1 %u %.*s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            status, static_cast<int>(reason.size()), reason.data());
    writebuf()->append(response.data(), response.size());
    close_after_reply_ = true;
    state(socks5_state::REQRES_SENT);
    com()->set_write_monitor(socket());
}

std::size_t HttpConnectServerCX::process_in() {
    if(state_ != socks5_state::INIT) {
        return 0;
    }

    std::string_view const data(
            reinterpret_cast<char const*>(readbuf()->data()), readbuf()->size());
    auto const headers_end = data.find("\r\n\r\n");
    if(headers_end == std::string_view::npos) {
        if(data.size() > max_connect_header_size) {
            send_error(431, "Request Header Fields Too Large");
            return data.size();
        }
        return 0;
    }

    auto const request_size = headers_end + 4;
    auto const line_end = data.find("\r\n");
    auto const request = HttpConnectRequest::parse(data.substr(0, line_end + 2));
    if(not request) {
        send_error(400, "Bad Request");
        return request_size;
    }

    socks_error_ = prepare_connect_target(request->host, request->port);
    if(socks_error_ != socks5_request_error::NONE) {
        send_error(502, "Bad Gateway");
    }

    return request_size;
}

std::size_t HttpConnectServerCX::process_socks_reply() {
    if(verdict_ == socks5_policy::ACCEPT) {
        // Unlike SOCKS, CONNECT must not report success before the upstream
        // TCP connection is established. ExplicitProxy sends the response
        // after the non-blocking connect completes.
        state(socks5_state::HANDOFF);
        com()->set_write_monitor(socket());
        return 0;
    } else {
        static constexpr std::string_view response =
                "HTTP/1.1 403 Forbidden\r\n"
                "Connection: close\r\nContent-Length: 0\r\n\r\n";
        writebuf()->append(response.data(), response.size());
        close_after_reply_ = true;
    }

    state(socks5_state::REQRES_SENT);
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
    socksServerCX::pre_write();
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
    return new HttpConnectServerCX(com()->slave(), s);
}

void MitmHttpConnectProxy::on_left_new(baseHostCX* just_accepted_cx) {
    auto* proxy = new HttpConnectProxy(com()->slave());
    just_accepted_cx->name();
    proxy->ladd(just_accepted_cx);
    add_proxy(proxy);
}
