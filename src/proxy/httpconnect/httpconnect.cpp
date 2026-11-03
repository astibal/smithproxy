#include <service/auth/broker_client.hpp>
#include <common/base64.hpp>
#include <service/http/webhooks.hpp>
#include <proxy/httpconnect/httpconnect.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <sstream>

namespace {

constexpr std::size_t max_connect_header_size = 8 * 1024;

std::string error_response(unsigned int status, std::string_view reason) {
    return string_format(
        "HTTP/1.1 %u %.*s\r\n%sConnection: close\r\nContent-Length: 0\r\n\r\n",
        status, static_cast<int>(reason.size()), reason.data(),
        status == 407 ? "Proxy-Authenticate: Basic realm=\"smithproxy\"\r\n" : "");
}

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

    send_response(error_response(status, reason));
}

void HttpConnectServerCX::send_response(std::string response) {

    if(auto* proxy = dynamic_cast<HttpConnectProxy*>(parent_proxy())) {
        proxy->connect_response(response, false);
        if(proxy->state().dead()) {
            error(true);
            return;
        }
    }

    writebuf()->append(response.data(), response.size());
    close_after_reply_ = true;
    state(explicit_state::REQRES_SENT);
    com()->set_write_monitor(socket());
}

HttpConnectServerCX::Authentication HttpConnectServerCX::authenticate_request(
        std::string_view headers, const HttpConnectRequest& target) {

    Authentication authentication;
    if(!proxy_authorization.load()) {
        return authentication;
    }

    const auto credentials = sx::auth::http_basic_credentials(headers);
    if(!credentials) {
        authentication.response = error_response(407, "Proxy Authentication Required");
        return authentication;
    }

    // Verify with AAA first. The webhook may veto acceptance, never grant it.
    const auto baseline = sx::auth::verify_proxy_credentials(
        credentials->username, credentials->password);

    const auto encoded_request = libbase64::encode<std::string, char, unsigned char, true>(
        reinterpret_cast<unsigned char const*>(headers.data()), headers.size());
    const nlohmann::json context = {
        {"host", target.host},
        {"port", target.port},
        {"request_base64", encoded_request}
    };

    const auto result = sx::http::webhooks::proxy_authentication(
        "http-connect", host(), port(), *credentials, baseline, context);

    authentication.accepted = result.status == sx::auth::Status::accepted;
    if(!authentication.accepted) {
        authentication.response = result.status == sx::auth::Status::rejected
            ? error_response(407, "Proxy Authentication Required")
            : error_response(503, "Authentication Service Unavailable");
    }

    return authentication;
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
    auto request = HttpConnectRequest::parse(data.substr(0, line_end + 2));
    if(not request) {
        send_error(400, "Bad Request");
        return request_size;
    }

    // Authentication and CONNECT observation are separate decisions. Even a
    // rejected request reaches the hook, but the native AAA result stays final.
    auto authentication = authenticate_request(data.substr(0, request_size), *request);

    if(auto* proxy = dynamic_cast<HttpConnectProxy*>(parent_proxy())) {
        const auto decision = proxy->connect_request(
            *this, data.substr(0, request_size), *request,
            authentication.accepted, authentication.response);

        using Action = sx::proxy::ProxyHooks::HttpConnectDecision::Action;
        if(proxy->state().dead()) {
            error(true);
            return request_size;
        }

        if(!authentication.response.empty()) {
            send_response(std::move(authentication.response));
            return request_size;
        }

        if(decision.action == Action::local_response) {
            send_response(decision.response);
            return request_size;
        }

        if(decision.action == Action::proceed) {
            request = HttpConnectRequest{decision.host, decision.port};
        }
    } else if(!authentication.response.empty()) {
        send_response(std::move(authentication.response));
        return request_size;
    }

    // setup_target() can replace this frontend before process_in() returns.
    // Publish the exact framing boundary first so bytes pipelined after the
    // CONNECT headers survive that handoff.
    req_hdr_size = request_size;
    request_error_ = prepare_connect_target(request->host, request->port);
    if(request_error_ != explicit_request_error::NONE) {
        if(request_error_ == explicit_request_error::LOCAL_DESTINATION)
            send_error(403, "Forbidden");
        else
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
        send_error(403, "Forbidden");
        return writebuf()->size();
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

std::string_view HttpConnectServerCX::upstream_policy_failure_response() const {

    return "HTTP/1.1 403 Forbidden\r\n"
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

HttpConnectProxy::~HttpConnectProxy() {

    connect_cleanup();
}

void HttpConnectProxy::shutdown() {

    // Object destruction can be deferred. Release the prelude with transport
    // shutdown, while the destructor remains a fallback for early failures.
    connect_cleanup();
    ExplicitProxy::shutdown();
}

void HttpConnectProxy::connect_cleanup() {

    if(!connect_observed_ || wh_start)
        return;
    connect_observed_ = false;

    // Ordinary connection-stop already releases an established setup. Only a
    // prelude that ends before setup needs its own cleanup exchange, including
    // requests whose reply was lost in transit.
    sx::proxy::ProxyHooks::HttpConnectArgs args;
    args.event = "abort";

    sx::proxy::ProxyHooks::http_connect(*this, args);
}

sx::proxy::ProxyHooks::HttpConnectDecision HttpConnectProxy::connect_request(
        HttpConnectServerCX& client, std::string_view request,
        const HttpConnectRequest& target, bool authenticated, std::string_view response) {

    connect_target_ = target;
    authentication_denied_ = !response.empty();
    connect_observed_ = sx::http::webhooks::is_enabled();

    sx::proxy::ProxyHooks::HttpConnectArgs args;
    args.event = "request";
    args.request = request;
    args.host = target.host;
    args.port = target.port;
    args.response = response;
    args.authenticated = authenticated;
    args.client = &client;

    auto decision = sx::proxy::ProxyHooks::http_connect(*this, args);

    if(!authentication_denied_ &&
       decision.action == sx::proxy::ProxyHooks::HttpConnectDecision::Action::proceed) {
        connect_target_ = {decision.host, decision.port};
    }

    return decision;
}

void HttpConnectProxy::connect_response(std::string& response, bool connected) {

    if(!connect_observed_ || connect_finished_)
        return;
    connect_finished_ = true;

    sx::proxy::ProxyHooks::HttpConnectArgs args;
    args.event = connected ? "connected" : "error";
    args.host = connect_target_.host;
    args.port = connect_target_.port;
    args.response = response;
    args.server = first_right();

    const auto decision = sx::proxy::ProxyHooks::http_connect(*this, args);

    if(!authentication_denied_ &&
       decision.action == sx::proxy::ProxyHooks::HttpConnectDecision::Action::send_response) {
        response = decision.response;
    }
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

int MitmHttpConnectProxy::handle_sockets_once(baseCom* c) {

    process_session_lists(*this);
    return ThreadedAcceptorProxy<HttpConnectProxy>::handle_sockets_once(c);
}
