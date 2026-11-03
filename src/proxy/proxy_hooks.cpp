#include <proxy/proxy_hooks.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/content_webhook_metadata.hpp>
#include <proxy/connection_start.hpp>
#include <proxy/directional_content.hpp>
#include <service/http/webhooks.hpp>
#include <socle/common/base64.hpp>

using namespace socle;

namespace sx::proxy {

using HttpApplication = sx::engine::http::app_HttpRequest;

namespace {

std::string b64_encode(buffer &buffer) {
    return libbase64::encode<std::string, char, unsigned char, true>(buffer.data(), buffer.size());
}

std::string b64_decode(std::string const& encoded) {
    // An empty replacement consumes the whole chunk. The decoder below expects
    // at least one base64 block, so handle this valid zero-byte value directly.
    if(encoded.empty()) return {};
    return libbase64::decode<std::string, char, unsigned char, false>(encoded);
}

// Metadata builders only describe the current payload; they never apply replies.
void add_content_ranges(nlohmann::json& info, const ProxyHooks::ContentArgs& args,
                        const MitmHostCX* left) {
    // H1/H2 framing belongs to FlowCtx on the left context. Only HTTP/3
    // carries the current payload observation on its individual stream.
    auto const* current = MitmHostCX::from_baseHostCX(args.cx);
    auto app = current
        ? std::dynamic_pointer_cast<HttpApplication>(current->engine().application_data)
        : nullptr;
    if(!app || app->version != HttpApplication::HTTP_VER::HTTP3) {
        app = left
            ? std::dynamic_pointer_cast<HttpApplication>(left->engine().application_data)
            : nullptr;
    }

    // An outer CONNECT request must not annotate bytes of the inner protocol.
    if(!app || !app->l7_payload_matches(args.data->string_view(), args.cx->meter_read_bytes))
        return;

    auto metadata = sx::proxy::l7_payload_metadata(
        app->l7_payload, app->l7_encoding, app->payload_annotations);
    for(auto& [key, value] : metadata.items())
        info[key] = std::move(value);
}

void add_content_http(nlohmann::json& info, const MitmHostCX* left) {
    if(!left) return;
    const auto app = std::dynamic_pointer_cast<HttpApplication>(
        left->engine().application_data);
    if(!app || !app->populated()) return;

    auto const http2 = app->version == sx::engine::http::app_HttpRequest::HTTP_VER::HTTP2;
    auto const http3 = app->version == sx::engine::http::app_HttpRequest::HTTP_VER::HTTP3;
    auto const prefix = http3 ? "flow.http3." :
                        http2 ? "flow.http2." : "flow.http1.";

    info[http3 ? "flow.http3" : http2 ? "flow.http2" : "flow.http1"] = true;

    auto put = [&](std::string const& field, std::string const& value) {
        if(!value.empty()) info[prefix + field] = value;
    };

    auto path = app->http_data.uri;
    if(!app->http_data.params.empty()) path += "?" + app->http_data.params;

    auto scheme = app->http_data.proto;
    if(scheme.size() >= 3 && scheme.compare(scheme.size() - 3, 3, "://") == 0) {
        scheme.resize(scheme.size() - 3);
    }

    put("method", app->http_data.method);
    put((http2 || http3) ? "authority" : "host", app->http_data.host);
    put("path", path);
    put("scheme", scheme);
    put("url", app->request());
    put("content_type", app->http_data.content_type);
    put("accept", app->http_data.accept);
    put("subprotocol", app->http_data.sub_proto);
}

void add_content_tls(nlohmann::json& info, const MitmHostCX* right) {
    if(!right) return;
    const auto* tls = dynamic_cast<SSLCom*>(right->com());
    if(!tls || tls->get_sni().empty()) return;

    info["flow.tls.sni"] = tls->get_sni();
}

} // namespace

struct ProxyHooks::StartReplyArgs {
    const sx::http::expected_reply& reply;
    bool local_rewrite = false;
};

// One synchronous content exchange. Both receivers share the same buffers and
// result flags, preserving the existing SIFT-before-webhook processing order.
struct ProxyHooks::ContentExchangeArgs {
    const ContentArgs& input;
    bool reverse_allowed = false;
    bool modified = false;
    bool reply_received = false;
};

struct ProxyHooks::ContentReplyArgs {
    ContentExchangeArgs& exchange;
    const sx::http::expected_reply& reply;
};

struct ProxyHooks::ContentActionArgs {
    ContentExchangeArgs& exchange;
    const nlohmann::json& body;
};

nlohmann::json ProxyHooks::start_details(const MitmProxy& proxy, const StartDetailsArgs&) {
    nlohmann::json info = {
        {"session", proxy.to_connection_label()}, {"phase", "setup"},
        {"policy", proxy.matched_policy()},
        {"webhook_control", {{"version", 1},
            {"mode", proxy.webhook_control_->strict() ? "strict" : "regular"},
            {"sequence", 0}, {"rewrite", false}}}
    };

    auto endpoint = [](auto const* host) {
        if (!host) return nlohmann::json(nullptr);

        return nlohmann::json{{"host", host->host()}, {"port", host->port()}};
    };
    info["source"] = endpoint(proxy.first_left());
    info["destination"] = endpoint(proxy.first_right());

    if (auto* left = proxy.first_left(); left && left->com()) {
        const auto type = left->com()->l4_proto();

        if (type == SOCK_STREAM) info["transport"] = "tcp";
        else if (type == SOCK_DGRAM) info["transport"] = "udp";
    }
    if (auto protocol = proxy.session_protocol(); !protocol.empty())
        info["protocol"] = std::string(protocol);

    // Preserve the distinction between the two TLS legs. Missing information
    // stays absent: plaintext/STARTTLS sessions need not have TLS metadata yet.
    auto tls_leg = [&](auto const* host, const char* name) {
        if (!host) return;

        auto* tls = dynamic_cast<SSLCom*>(host->com());

        if (!tls) return;

        auto& leg = info["tls"][name];
        leg = nlohmann::json::object();

        if (!tls->get_sni().empty()) leg["sni"] = tls->get_sni();
        if (auto alpn = tls->negotiated_alpn(); !alpn.empty()) leg["alpn"] = alpn;
    };
    tls_leg(proxy.first_left(), "client");
    tls_leg(proxy.first_right(), "server");

    if (!proxy.ja4.ClientHello.empty()) info["ja4_ch"] = proxy.ja4.ClientHello;
    if (!proxy.ja4.ServerHello.empty()) info["ja4_sh"] = proxy.ja4.ServerHello;

    proxy.add_webhook_stream_details(info);
    return {{"info", std::move(info)}};
}

bool ProxyHooks::start_reply(MitmProxy& proxy, const StartReplyArgs& args) {
    if(!args.reply) return false;

    auto result = sx::proxy::parse_setup_reply(
        args.reply->response.first, args.reply->response.second);
    proxy.webhook_control_->apply(result.body);

    switch(result.action) {
        case setup_action::accept:
            proxy.webhook_rewrite_allowed_ = result.rewrite;
            proxy.flow_ctx_->allow_rewrite(args.local_rewrite || result.rewrite);
            return true;
        case setup_action::drop:
            proxy.state().dead(true);
            return true;
        case setup_action::not_interested:
            // Strict mode requires continued content delivery.
            if(proxy.webhook_control_->strict()) return false;
            proxy.webhook_content_wanted_ = false;
            return true;
        case setup_action::invalid:
            return false;
    }
    return false;
}

bool ProxyHooks::start(MitmProxy& proxy, const StartArgs&) {

    // Local replacement rules are known before content arrives. They need the
    // same two views, independently of a remote receiver's rewrite permission.
    const bool local_rewrite = proxy.content_rule() && !proxy.content_rule()->empty();
    proxy.flow_ctx_->allow_rewrite(local_rewrite);

    const bool enabled = sx::http::webhooks::is_enabled();
    if (!enabled && !sx::http::webhooks::sift_enabled()) return true;

    auto& log = proxy.log_content;
    const auto details = proxy.connection_start_details();
    proxy.wh_start = true;

    // Unlike the old asynchronous notification, this gate completes before
    // FlowCtx::begin or an exclusive stream handler can consume content.
    // The reply callback runs within send_action_wait, not after this returns.
    bool valid_reply = false;

    if (enabled) {
        sx::http::webhooks::send_action_wait("connection-start", proxy.to_connection_ID(), details,
            [&](sx::http::expected_reply reply) {
                StartReplyArgs reply_args{reply};
                reply_args.local_rewrite = local_rewrite;
                valid_reply = start_reply(proxy, reply_args);
            });

        if (!valid_reply) {
            _war("connection-start: missing or invalid setup reply (%s)",
                 proxy.webhook_control_->strict() ? "fail-closed" : "fail-open");
            if (proxy.webhook_control_->strict()) proxy.state().dead(true);
        }
    }

    // SIFT remains a notification consumer, not a second setup authority.
    sx::http::webhooks::send_sift_action("connection-start", proxy.to_connection_ID(), details);

    if (proxy.state().dead()) proxy.shutdown();

    return !proxy.state().dead();
}

void ProxyHooks::stop(const MitmProxy& proxy, const StopArgs&) {

    nlohmann::json j;
    auto cl = proxy.to_connection_label();

    uint64_t uB = 0L;
    uint64_t dB = 0L;
    std::optional<nlohmann::json> l7;
    std::optional<nlohmann::json> tls;

    auto const* l = proxy.first_left();
    if(l) {
        uB = l->meter_read_bytes;
        dB = l->meter_write_bytes;

        if(auto app = l->engine().application_data; app) {
            l7 =  { { "app", app->protocol() },
                    { "details", app->requests_all() },
                    { "signatures", l->matched_signatures() }
            };
            if(! app->custom_list_name().empty()) {
                l7.value()[app->custom_list_name()] = app->custom_list();
            }
        }
    }
    auto const* r = proxy.first_right();
    if(r){

        if(auto* scom = dynamic_cast<SSLCom*>(r->com()); scom) {
            nlohmann::json x;
            x["sni"] = scom->get_sni();
            tls = x;
        }
    }

    j["info"] = { {"session", cl },
                  {"policy", proxy.matched_policy() },
                  { "bytes_up", uB },
                  { "bytes_down", dB },
                  { "ja4_ch", proxy.ja4.ClientHello },
                  { "ja4_ch_ignore_sni", proxy.acct_opts.ja4_clienthello_ignore_sni },
                  { "ja4_sh", proxy.ja4.ServerHello },
    };

    proxy.add_webhook_stream_details(j["info"]);
    if(tls.has_value())  j["info"]["tls"] = tls.value();
    if(l7.has_value())  j["info"]["l7"] = l7.value();
    if(auto classifications = proxy.sift_classifications(); !classifications.empty()) {
        j["info"]["classification"]["sift"] = std::move(classifications);
    }
    if(auto classifications = proxy.lored_classifications(); !classifications.empty()) {
        j["info"]["classification"]["lored"] = std::move(classifications);
    }

    if(sx::http::webhooks::is_enabled())
        sx::http::webhooks::send_action("connection-stop", proxy.to_connection_ID(), j, proxy.webhook_control_);
    sx::http::webhooks::send_sift_action("connection-stop", proxy.to_connection_ID(), j);

    proxy.wh_stop = true;
}

void ProxyHooks::readiness(const MitmProxy& proxy, const ReadinessArgs& args) {
    const bool client = args.side == 'l' || args.side == 'x';
    nlohmann::json info = {
        {"session", proxy.to_connection_label()}, {"side", client ? "L" : "R"},
        {"transport_lifecycle", {{"version", 1}, {"event", args.event},
            {"attempt", args.attempt}, {"host", args.cx->host()}, {"port", args.cx->port()}}}
    };
    proxy.add_webhook_stream_details(info);
    // These are native observations, not HTTP CONNECT or mitmproxy callbacks.
    // Keep the existing connection-info response/control handling.
    sx::http::webhooks::send_action("connection-info", proxy.to_connection_ID(),
                                   {{"info", std::move(info)}}, proxy.webhook_control_);
}

nlohmann::json ProxyHooks::content_details(MitmProxy& proxy, const ContentExchangeArgs& args) {
    nlohmann::json j;
    auto cl = proxy.to_connection_label();
    j["info"] = {
        { "session", cl },
        { "side", string_format("%c", from_side(args.input.side)) },
        { "payload_layer", std::string(args.input.payload_layer) },
        { "L7_payload_start", nlohmann::json::array({-1}) },
        { "L7_payload_end", nlohmann::json::array({-1}) },
        { "L7_encoding", nlohmann::json::array({""}) },
        { "content_annotations", nlohmann::json::array() }
    };
    proxy.add_webhook_stream_details(j["info"]);
    if(args.input.regular_webhook) {
        // Advertise support before Spider may publish its first stateful rewrite.
        j["info"]["webhook_control"] = {
            {"version", 1}, {"mode", proxy.webhook_control_->strict() ? "strict" : "regular"},
            {"sequence", ++proxy.webhook_control_->content_sequence},
            {"rewrite", proxy.webhook_rewrite_allowed_},
            {"content-reverse", args.reverse_allowed}
        };
    }

    add_content_ranges(j["info"], args.input, proxy.first_left());
    add_content_tls(j["info"], proxy.first_right());
    add_content_http(j["info"], proxy.first_left());
    return j;
}

void ProxyHooks::content_reverse(MitmProxy& proxy, const ContentActionArgs& args) {
    auto& exchange = args.exchange;
    const auto& input = exchange.input;
    auto& log = proxy.log_content;

    try {
        if(!input.regular_webhook || input.sift || !exchange.reverse_allowed) {
            throw std::logic_error("Reverse content requires advertised rewrite views");
        }

        auto output = sx::proxy::DirectionalContent::parse(args.body);
        // Stage only. The proxy publishes input metadata and completes filtering
        // before touching the reverse view.
        input.reverse_output->assign(output.reverse.data(), output.reverse.size());
        input.data->assign(output.forward.data(), output.forward.size());
        exchange.modified = true;
    }
    catch(std::exception const& error) {
        _err("Invalid directional webhook output: %s", error.what());
        input.reverse_output->clear();
        proxy.state().dead(true);
    }
}

void ProxyHooks::content_action(MitmProxy& proxy, const ContentActionArgs& args) {
    auto& exchange = args.exchange;
    const auto& input = exchange.input;
    const auto& body = args.body;
    auto& data = *input.data;
    auto& log = proxy.log_content;

    // Directional output takes precedence over ordinary actions.
    if(body.contains("content-reverse")) {
        content_reverse(proxy, args);
        return;
    }
    if(!body.contains("action")) return;

    const auto& action = body["action"];
    if(action == "drop") {
        proxy.state().dead(true);
        return;
    }

    std::optional<std::string> replacement;
    const auto content = body.find("content");
    if(content != body.end() && content->is_string()) {
        replacement = b64_decode(content->get_ref<const std::string&>());
    }

    // Same-size replace is an intentional low-level escape hatch, not a claim
    // of protocol safety. Compare decoded bytes, not the base64 envelope size.
    const bool same_size_replace = action == "replace" && replacement &&
        replacement->size() == data.size();
    const bool changes_stream = action == "replace" || action == "discard" ||
        action == "need-more" || body.contains("content");
    if(changes_stream && (input.sift || (!proxy.webhook_rewrite_allowed_ && !same_size_replace))) {
        _err("content mutation requires setup rewrite permission or a same-size replace");
        proxy.state().dead(true);
        return;
    }

    if(input.regular_webhook && action == "not-interested" && !proxy.webhook_control_->strict()) {
        proxy.webhook_content_wanted_ = false;
        _dia("webhook content: peer declined future content for this connection");
        return;
    }
    if(action == "discard" || (input.regular_webhook && action == "need-more")) {
        // need-more consumes this chunk too, but keeps future callbacks enabled.
        // The receiver may return the accumulated bytes in a later replacement.
        data.size(0);
        exchange.modified = true;
        if(action == "need-more")
            _dia("webhook content: chunk consumed; awaiting more content");
        return;
    }
    if(!replacement) {
        _dia("webhook content-replace: no replacement body received");
        return;
    }

    const auto& decoded = *replacement;
    _dia("webhook content-replace: received %dB of replacement data", decoded.size());
    {
        auto& log = proxy.log_content_dump;
        _deb("webhook content-replace: replacement: %s\r\n",
             hex_dump((unsigned char*)decoded.data(), decoded.size(), 4, 0, true).c_str());
    }
    data.assign(decoded.data(), decoded.size());
    exchange.modified = true;
}

void ProxyHooks::content_reply(MitmProxy& proxy, const ContentReplyArgs& args) {
    if(!args.reply) return;

    auto& exchange = args.exchange;
    const auto& input = exchange.input;
    const auto& response = args.reply->response;
    auto& log = proxy.log_content;
    _dia("webhook content-replace: response %d", response.first);

    if(response.first < 200 || response.first >= 300) {
        // SIFT can return classification information even with an HTTP error.
        if(input.sift) {
            auto body = nlohmann::json::parse(response.second, nullptr, false);
            if(!body.is_discarded() && proxy.apply_sift_reply(body))
                proxy.publish_sift_classifications();
        }
        return;
    }

    auto body = nlohmann::json::parse(response.second, nullptr, false);
    if(!body.is_object()) {
        _err("MitmProxy::content_webhook: response body is invalid");
        return;
    }

    // Apply control and classification before any content action, as before.
    if(input.regular_webhook) {
        proxy.webhook_control_->apply(body);
        exchange.reply_received = true;
    }
    if(input.sift && proxy.apply_sift_reply(body))
        proxy.publish_sift_classifications();

    ContentActionArgs action_args{exchange, body};
    content_action(proxy, action_args);
}

bool ProxyHooks::content(MitmProxy& proxy, const ContentArgs& args) {
    ContentExchangeArgs exchange{args};
    exchange.reverse_allowed = proxy.webhook_rewrite_allowed_ && proxy.flow_ctx_->can_inject() &&
        proxy.left_sockets.size() + proxy.left_delayed_accepts.size() == 1 &&
        proxy.right_sockets.size() + proxy.right_delayed_accepts.size() == 1 &&
        args.cx->com()->l4_proto() == SOCK_STREAM;

    auto j = content_details(proxy, exchange);
    auto& buffer = *args.data;
    auto response_hook = [&](sx::http::expected_reply reply) {
        ContentReplyArgs reply_args{exchange, reply};
        content_reply(proxy, reply_args);
    };

    if(args.sift) {
        const bool right_side = args.side == side_t::RIGHT;
        auto& sent_bytes = right_side
            ? proxy.sift_ctl_.payload_right_bytes
            : proxy.sift_ctl_.payload_left_bytes;
        const auto payload_limit =
            MitmProxy::sift_ctl_t::payload_limit_per_direction().load(std::memory_order_relaxed);

        if(sent_bytes <= payload_limit) {
            sent_bytes += buffer.size();
            sx::http::webhooks::send_sift_content_wait(
                proxy.to_connection_ID(), j,
                std::string_view(reinterpret_cast<const char*>(buffer.data()), buffer.size()),
                response_hook);
        }
    }
    if(args.regular_webhook) {
        const auto binary_sent = sx::http::webhooks::send_content_wait(
            proxy.to_connection_ID(), j,
            std::string_view(reinterpret_cast<const char*>(buffer.data()), buffer.size()), response_hook);
        if(!binary_sent) {
            j["info"]["content"] = b64_encode(buffer);
            sx::http::webhooks::send_action_wait(
                "connection-content", proxy.to_connection_ID(), j, response_hook);
        }
    }

    // No response (including a skipped request), HTTP failure or invalid JSON:
    // strict connections must not forward the unprocessed content.
    if(args.regular_webhook && !exchange.reply_received && proxy.webhook_control_->strict()) {
        buffer.size(0);
        proxy.state().dead(true);
        return true;
    }

    return exchange.modified;
}

} // namespace sx::proxy
