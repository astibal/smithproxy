#include <proxy/proxy_hooks.hpp>
#include <proxy/retirement.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/content_webhook_metadata.hpp>
#include <proxy/connection_start.hpp>
#include <proxy/httpconnect/httpconnectrequest.hpp>
#include <proxy/httpconnect/httpconnectreply.hpp>
#include <proxy/directional_content.hpp>
#include <service/http/webhooks.hpp>
#include <socle/common/base64.hpp>

#include <netdb.h>

using namespace socle;

namespace sx::proxy {

using HttpApplication = sx::engine::http::app_HttpRequest;

namespace {

bool valid_upstream_sni(std::string_view name) {

    if(name.empty()) return true;
    if(name.size() > 253 || inet::is_ipv4_address(std::string(name)) ||
       inet::is_ipv6_address(std::string(name))) {
        return false;
    }

    std::size_t label = 0;
    char previous = '.';
    for(char ch : name) {
        if(ch == '.') {
            if(label == 0 || previous == '-') return false;
            label = 0;
        } else {
            const bool letter = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
            const bool digit = ch >= '0' && ch <= '9';
            if((!letter && !digit && ch != '-') || (label == 0 && ch == '-')) return false;
            if(++label > 63) return false;
        }
        previous = ch;
    }

    return previous != '-';
}

bool alpn_subset(std::string_view proposed, std::string_view offered) {

    if(proposed.size() > 65535) return false;
    while(!proposed.empty()) {
        const auto length = static_cast<unsigned char>(proposed.front());
        if(length == 0 || proposed.size() <= length) return false;
        const auto protocol = proposed.substr(1, length);
        proposed.remove_prefix(length + 1);

        bool found = false;
        auto remaining = offered;
        while(!remaining.empty()) {
            const auto size = static_cast<unsigned char>(remaining.front());
            if(size == 0 || remaining.size() <= size) return false;
            found = found || remaining.substr(1, size) == protocol;
            remaining.remove_prefix(size + 1);
        }
        if(!found) return false;
    }

    return true;
}

nlohmann::json socket_endpoint(baseHostCX* cx, bool peer) {

    if(!cx || cx->socket() < 0)
        return nullptr;

    sockaddr_storage address{};
    socklen_t size = sizeof(address);
    const auto status = peer
        ? ::getpeername(cx->socket(), reinterpret_cast<sockaddr*>(&address), &size)
        : ::getsockname(cx->socket(), reinterpret_cast<sockaddr*>(&address), &size);

    if(status != 0)
        return nullptr;

    char host[NI_MAXHOST]{};
    char port[NI_MAXSERV]{};
    if(::getnameinfo(reinterpret_cast<sockaddr*>(&address), size, host, sizeof(host),
                     port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        return nullptr;

    return nlohmann::json::array({host, std::stoi(port)});
}

std::string certificate_pem(X509* certificate) {

    auto output = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_mem()), BIO_free);
    if(!output || !PEM_write_bio_X509(output.get(), certificate)) {
        return {};
    }

    char* bytes = nullptr;
    const auto length = BIO_get_mem_data(output.get(), &bytes);
    return length > 0 ? std::string(bytes, static_cast<std::size_t>(length)) : std::string{};
}

std::string b64_encode(buffer &buffer) {
    return libbase64::encode<std::string, char, unsigned char, true>(buffer.data(), buffer.size());
}

std::string b64_decode(std::string const& encoded) {
    // An empty replacement consumes the whole chunk. The decoder below expects
    // at least one base64 block, so handle this valid zero-byte value directly.
    if(encoded.empty()) return {};
    return libbase64::decode<std::string, char, unsigned char, false>(encoded);
}

std::string b64_encode_text(std::string_view bytes) {
    return libbase64::encode<std::string, char, unsigned char, true>(
        reinterpret_cast<unsigned char const*>(bytes.data()), bytes.size());
}

// Convert the API-shaped reply once, then reuse the native offer validator.
bool decode_client_hello_reply(nlohmann::json& body) {

    if(!body.is_object() || !body.contains("schema") ||
       !body["schema"].is_number_integer() || body["schema"] != 2 ||
       !body.contains("client_hello") || !body["client_hello"].is_object()) {
        return false;
    }

    const auto& draft = body["client_hello"];
    if(!draft.contains("decision") || !draft["decision"].is_string() ||
       !draft.contains("alpn_offers") || !draft["alpn_offers"].is_array() ||
       !draft.contains("sni") || !draft.contains("openssl_cipher_list")) {
        return false;
    }

    const auto action = draft["decision"].get<std::string>();
    if(action != "continue" && action != "bypass" && action != "terminate") return false;

    std::string protocols;
    for(const auto& encoded : draft["alpn_offers"]) {
        if(!encoded.is_string() || encoded.get_ref<const std::string&>().size() > 340) return false;
        const auto value = b64_decode(encoded.get<std::string>());
        if(value.empty() || value.size() > 255 || b64_encode_text(value) != encoded.get<std::string>()) {
            return false;
        }

        protocols.push_back(static_cast<char>(value.size()));
        protocols += value;
        if(protocols.size() > 65535) return false;
    }

    body["proceed"] = action != "terminate";
    body["ignore_connection"] = action == "bypass";
    body["upstream"] = {{"sni", draft["sni"]},
        {"alpn_base64", protocols.empty() ? std::string{} : b64_encode_text(protocols)},
        {"openssl_cipher_list", draft["openssl_cipher_list"]}};
    return true;
}

// Schema 2 mirrors the native API. Conversion stays at the webhook boundary;
// the existing offer validators and observers continue to receive schema 1.
nlohmann::json handshake_metadata(const nlohmann::json& observation, bool quic) {

    const auto& envelope = observation.at("envelope");
    const bool start = envelope.at("event") == "start";
    nlohmann::json value;

    // Start exposes effective settings; outcomes carry immutable handshake facts.
    if(start) {
        value = {{"sni", observation.value("sni", nlohmann::json(""))},
                 {"alpn_offers", nlohmann::json::array()}, {"decision", "continue"}};

        const auto cipher_key = quic ? "openssl_ciphersuites" : "openssl_cipher_list";
        value[cipher_key] = nullptr;

        // Only upstream starts have an editable offer. Client-facing starts
        // retain the defaults above and expose no upstream cipher expression.
        if(observation.contains("upstream")) {
            const auto& offer = observation.at("upstream");
            value["sni"] = offer.at("sni");
            value[cipher_key] = offer.at(quic ? "ciphers" : "openssl_cipher_list");

            // The API uses individual base64 ALPN values for both transports.
            // QUIC supplies one protocol; TLS supplies a length-prefixed list.
            if(quic) {
                value["alpn_offers"].push_back(b64_encode_text(offer.at("alpn").get<std::string>()));
            } else {
                const auto protocols = b64_decode(offer.at("alpn_base64").get<std::string>());

                for(std::size_t offset = 0; offset < protocols.size();) {
                    const auto length = static_cast<unsigned char>(protocols[offset++]);
                    if(!length || offset + length > protocols.size()) {
                        throw std::runtime_error("Invalid native TLS ALPN offer");
                    }

                    value["alpn_offers"].push_back(b64_encode_text(protocols.substr(offset, length)));
                    offset += length;
                }
            }
        }
    } else {
        value = observation;
        value.erase("envelope");
        value.erase("protocol");

        // Normalize the selected protocol without changing the observed facts.
        value["alpn"] = quic
            ? nlohmann::json(b64_encode_text(observation.value("alpn", std::string{})))
            : observation.at("alpn_base64");
        value.erase("alpn_base64");
        value["decision"] = "continue";
    }

    return {{"schema", 2}, {"envelope", envelope}, {start ? "start" : "outcome", std::move(value)}};
}

bool decode_handshake_reply(nlohmann::json& body, bool start, bool upstream, bool quic) {

    const auto key = start ? "start" : "outcome";
    if(!body.is_object() || body.value("schema", nlohmann::json()) != 2 ||
       !body.contains(key) || !body[key].is_object()) return false;

    // Validate the committed decision before considering mutable settings.
    const auto& draft = body[key];
    if(!draft.contains("decision") || !draft["decision"].is_string()) return false;

    const auto decision = draft["decision"].get<std::string>();
    if(decision != "continue" && decision != "terminate") return false;

    body["proceed"] = decision == "continue";
    if(!start || !upstream || decision == "terminate") return true;

    // Only an accepted upstream start may replace the outgoing offer.
    if(!draft.contains("sni") || !draft["sni"].is_string()) return false;

    // Reuse ClientHello validation for TCP TLS, then remove its temporary keys.
    if(!quic) {
        body["client_hello"] = draft;
        const bool valid = decode_client_hello_reply(body);
        body.erase("client_hello");
        body.erase("ignore_connection");
        return valid;
    }

    // QUIC supports one ALPN value. Require canonical base64 and the same
    // protocol length limit as the native observer before publishing settings.
    if(!draft.contains("alpn_offers") || !draft["alpn_offers"].is_array() ||
       draft["alpn_offers"].size() != 1 || !draft["alpn_offers"][0].is_string() ||
       !draft.contains("openssl_ciphersuites")) return false;

    const auto encoded = draft["alpn_offers"][0].get<std::string>();
    if(encoded.size() > 340) return false;

    const auto alpn = b64_decode(encoded);
    if(alpn.empty() || alpn.size() > 255 || b64_encode_text(alpn) != encoded) return false;

    body["upstream"] = {{"sni", draft["sni"]}, {"alpn", alpn},
                        {"ciphers", draft["openssl_ciphersuites"]}};
    return true;
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

struct ProxyHooks::HttpConnectReplyArgs {
    const HttpConnectArgs& input;
    const sx::http::expected_reply& reply;
    const nlohmann::json& envelope;
    HttpConnectDecision& decision;
};

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

nlohmann::json ProxyHooks::http_connect_details(const MitmProxy& proxy, const HttpConnectArgs& args) {

    const auto id = proxy.to_connection_ID();
    const nlohmann::json envelope = {
        {"version", 1},
        {"delivery", "http-connect"},
        {"connection_id", id},
        {"exchange_id", 1},
        {"event", args.event},
        {"mode", "regular"}
    };

    nlohmann::json observation = {
        {"envelope", envelope},
        {"target", {args.host, args.port}},
        {"authenticated", args.authenticated},
        {"response_base64", args.response.empty()
            ? nlohmann::json(nullptr)
            : nlohmann::json(b64_encode_text(args.response))}
    };

    if(args.event == "request") {
        observation["request_base64"] = b64_encode_text(args.request);
        observation["client_peername"] = socket_endpoint(args.client, true);
        observation["client_sockname"] = socket_endpoint(args.client, false);
    }

    if(args.event == "connected") {
        observation["peername"] = socket_endpoint(args.server, true);
        observation["sockname"] = socket_endpoint(args.server, false);
    }

    nlohmann::json details = {{"http_connect", observation}};
    if(args.client) {
        details["info"]["session"] = "tcp_[" + args.client->host() + "]:" + args.client->port() +
            "+tcp_[" + std::string(args.host) + "]:" + std::to_string(args.port);
    }

    return details;
}

void ProxyHooks::http_connect_reply(MitmProxy& proxy, const HttpConnectReplyArgs& args) {

    // Bound and decode the complete callback reply before inspecting its decision.
    const auto& reply = args.reply;
    if(!reply || reply->response.first != 200)
        return;

    const auto& bytes = reply->response.second;
    if(bytes.size() > 360 * 1024)
        return;

    auto body = nlohmann::json::parse(bytes, nullptr, false);
    if(body.is_discarded() || !body.is_object())
        return;

    try {
        // A valid decision must belong to this exact connection and event.
        if(body.at("action") != "http-connect" || body.at("id") != proxy.to_connection_ID() ||
           body.at("envelope") != args.envelope)
            return;

        const auto& result = body.at("decision");
        const auto action = result.at("action").get<std::string>();
        HttpConnectDecision candidate;

        if(args.input.event == "request" && action == "kill") {
            candidate.action = HttpConnectDecision::Action::kill;
        } else if(args.input.event == "request" && action == "continue") {
            // Reuse the native authority parser for any addon-selected target.
            const auto& target = result.at("target");
            if(!target.is_array() || target.size() != 2 || !target[1].is_number_integer() ||
               target[1] < 1 || target[1] > 65535)
                return;

            const auto host = target[0].get<std::string>();
            const auto port = target[1].get<int>();
            if(host.size() > 255 || port < 1 || port > 65535)
                return;

            const auto authority = host.find(':') == std::string::npos ? host : "[" + host + "]";
            const auto parsed = HttpConnectRequest::parse(
                "CONNECT " + authority + ":" + std::to_string(port) + " HTTP/1.1");
            if(!parsed)
                return;

            candidate.action = HttpConnectDecision::Action::proceed;
            candidate.host = parsed->host;
            candidate.port = parsed->port;
        } else if((args.input.event == "request" && action == "local-response") ||
                  (args.input.event != "request" && action == "send-response")) {
            // Validate both encoding and HTTP framing before replacing any bytes.
            const auto encoded = result.at("response_base64").get<std::string>();
            if(encoded.empty() || encoded.size() > 349528)
                return;

            candidate.response = libbase64::decode<std::string, char, unsigned char, true>(encoded);
            if(b64_encode_text(candidate.response) != encoded ||
               !valid_connect_reply(candidate.response))
                return;

            candidate.action = args.input.event == "request"
                ? HttpConnectDecision::Action::local_response
                : HttpConnectDecision::Action::send_response;
        } else {
            return;
        }

        // Publish only after every field in the candidate has passed validation.
        args.decision = std::move(candidate);
    } catch(const std::exception&) {
        // A malformed decision is never partially applied.
    }
}

ProxyHooks::HttpConnectDecision ProxyHooks::http_connect(
        MitmProxy& proxy, const HttpConnectArgs& args) {

    HttpConnectDecision decision;
    if(!sx::http::webhooks::is_enabled())
        return decision;

    try {
        const auto details = http_connect_details(proxy, args);
        const auto& envelope = details.at("http_connect").at("envelope");

        sx::http::webhooks::send_action_wait("http-connect", proxy.to_connection_ID(), details,
            [&](sx::http::expected_reply reply) {
                HttpConnectReplyArgs reply_args{args, reply, envelope, decision};

                http_connect_reply(proxy, reply_args);
            });
    } catch(const nlohmann::json::exception&) {
        // A client-supplied hostname may not be valid UTF-8. An unencodable
        // observation follows the same policy as an unavailable callback.
    }

    // Invalid/unavailable callbacks retain the native decision unless a prior
    // hook has already negotiated strict control over this connection.
    if(decision.action == HttpConnectDecision::Action::kill ||
       (decision.action == HttpConnectDecision::Action::unavailable && proxy.webhook_control_->strict())) {
        proxy.state().dead(true);
    }
    return decision;
}

bool ProxyHooks::start_reply(MitmProxy& proxy, const StartReplyArgs& args) {
    if(!args.reply) return false;

    auto result = sx::proxy::parse_setup_reply(
        args.reply->response.first, args.reply->response.second);
    proxy.webhook_control_->apply(result.body);

    switch(result.action) {
        case setup_action::accept: {
            // Older receivers may use strict content control without knowing
            // this newer synchronous lifecycle contract. Require version 1.
            const auto control = result.body.find("control");
            if(control != result.body.end()) {
                const auto version = control->find("server_lifecycle");
                proxy.webhook_server_lifecycle_ = version != control->end() &&
                    version->is_number_integer() && *version == 1;

                const auto tls = control->find("tls_lifecycle");
                proxy.webhook_tls_lifecycle_ = tls != control->end() &&
                    tls->is_number_integer() && *tls == 1;

                const auto schema = control->find("tls_schema");
                proxy.webhook_tls_meta_ = schema != control->end() &&
                    schema->is_number_integer() && *schema == 2;

                const auto hello = control->find("tls_clienthello");
                proxy.webhook_tls_clienthello_ = hello != control->end() &&
                    hello->is_number_integer() && *hello == 1;

                const auto hello_schema = control->find("tls_clienthello_schema");
                proxy.webhook_tls_clienthello_meta_ = proxy.webhook_tls_clienthello_ &&
                    hello_schema != control->end() && hello_schema->is_number_integer() && *hello_schema == 2;

                const auto start = control->find("tls_start_server");
                proxy.webhook_tls_start_server_ = start != control->end() &&
                    start->is_number_integer() && *start == 1;

                const auto client_start = control->find("tls_start_client");
                proxy.webhook_tls_start_client_ = client_start != control->end() &&
                    client_start->is_number_integer() && *client_start == 1;

                proxy.tls_observer_enabled(proxy.webhook_tls_clienthello_ ||
                    proxy.webhook_tls_start_server_ || proxy.webhook_tls_start_client_);
            }

            proxy.webhook_rewrite_allowed_ = result.rewrite;
            proxy.flow_ctx_->allow_rewrite(args.local_rewrite || result.rewrite);
            return true;
        }
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

ProxyHooks::Epitaph ProxyHooks::prepare_stop(const MitmProxy& proxy, const StopArgs&) {

    nlohmann::json j;
    auto cl = proxy.to_connection_label();

    uint64_t uB = 0L;
    uint64_t dB = 0L;
    auto const* l = proxy.first_left();
    if(l) {
        uB = l->meter_read_bytes;
        dB = l->meter_write_bytes;
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
    return {proxy.to_connection_ID(), std::move(j), nullptr};
}

void ProxyHooks::enrich_stop(Epitaph& epitaph, const MitmProxy& proxy) {
    // Optional application metadata must never prevent the basic terminal event.
    auto& info = epitaph.details["info"];
    if(auto const* l = proxy.first_left(); l && l->engine().application_data) {
        auto app = l->engine().application_data;
        nlohmann::json l7 = {{"app", app->protocol()},
                            {"details", app->requests_all()},
                            {"signatures", l->matched_signatures()}};
        if(!app->custom_list_name().empty()) l7[app->custom_list_name()] = app->custom_list();
        info["l7"] = std::move(l7);
    }
    if(auto const* r = proxy.first_right(); r) {
        if(auto* ssl = dynamic_cast<SSLCom*>(r->com()); ssl)
            info["tls"]["sni"] = ssl->get_sni();
    }
    if(auto classifications = proxy.sift_classifications(); !classifications.empty())
        info["classification"]["sift"] = std::move(classifications);
    if(auto classifications = proxy.lored_classifications(); !classifications.empty())
        info["classification"]["lored"] = std::move(classifications);
}

void ProxyHooks::stop(const Epitaph& epitaph, const StopArgs&) {

    // Each sink is independent. Failure to serialize filter data or submit one
    // sink must not suppress the terminal notification to the other sink.
    const auto attempt = [](const char* stage, auto&& operation) noexcept {
        retirement_step(operation, [&] { Log::get()->events().insert(ERR, "ProxyHooks::stop: failed %s", stage); });
    };
    if(sx::http::webhooks::is_enabled()) {
        if(!epitaph.filter_info.is_null()) {
            attempt("filter notification", [&] {
                sx::http::webhooks::send_action(
                    "connection-info", epitaph.connection_id, epitaph.filter_info);
            });
        }
        attempt("webhook stop", [&] {
            sx::http::webhooks::send_action(
                "connection-stop", epitaph.connection_id, epitaph.details);
        });
    }
    attempt("Sift stop", [&] {
        sx::http::webhooks::send_sift_action(
            "connection-stop", epitaph.connection_id, epitaph.details);
    });
}

sx::auth::Result ProxyHooks::authentication(const baseHostCX& client,
                                           const AuthenticationArgs& args) {

    if(!sx::http::webhooks::is_enabled()) {
        return args.baseline;
    }

    // One synchronous exchange owns both its credentials and its response.
    // No callback captures a frontend that target setup may later replace.
    static std::atomic_uint64_t sequence{0};
    const auto id = "auth-" + std::to_string(getpid()) + "-" +
                    std::to_string(++sequence);
    std::string status = "unavailable";
    if(args.baseline.status == sx::auth::Status::accepted) status = "accepted";
    if(args.baseline.status == sx::auth::Status::rejected) status = "rejected";

    nlohmann::json authentication = {
        {"version", 1},
        {"protocol", args.protocol},
        {"username", args.credentials.username},
        {"password", args.credentials.password},
        {"status", status},
        {"identity", args.baseline.identity},
        {"groups", args.baseline.groups},
        {"peer", {{"host", client.host()}, {"port", client.port()}}}
    };
    if(!args.protocol_context.is_null()) {
        authentication["http_connect"] = args.protocol_context;
    }

    const nlohmann::json event = {
        {"action", "proxy-authentication"}, {"id", id},
        {"source", sx::http::webhooks::get_hostid()}, {"type", "proxy"},
        {"details", {{"authentication", authentication}}}
    };

    sx::auth::Result observed;
    observed.error = "Authentication webhook unavailable";
    std::string payload;
    try {
        payload = event.dump();
    } catch (const nlohmann::json::exception&) {
        // SOCKS credentials are arbitrary bytes; invalid UTF-8 must not
        // escape the frontend or accidentally turn into permission.
        if(args.baseline.status != sx::auth::Status::accepted) return args.baseline;
        return observed;
    }

    auto settings = sx::http::AsyncRequest::settings_snapshot();
    settings.sensitive = true;
    std::stringstream trace;
    sx::http::AsyncRequest::emit_url_wait_log(settings, payload, trace,
        [&](sx::http::expected_reply const& reply) {
            if(!reply || reply->response.first != 200) return;

            const auto body = nlohmann::json::parse(reply->response.second, nullptr, false);
            if(!body.is_object() || body.value("action", "") != "proxy-authentication" ||
               body.value("id", "") != id || !body.contains("version") ||
               !body["version"].is_number_integer() || body["version"] != 1 ||
               !body.contains("decision") || !body["decision"].is_string()) return;

            const auto decision = body["decision"].get<std::string>();
            if(decision == "accept") {
                observed = args.baseline;
            } else if(decision == "reject") {
                observed = {};
                observed.status = sx::auth::Status::rejected;
            }
        });

    // Even a valid acceptance cannot override rejected/unavailable AAA.
    if(args.baseline.status != sx::auth::Status::accepted) return args.baseline;
    return observed;
}


bool ProxyHooks::server(MitmProxy& proxy, const ServerArgs& args) {

    const nlohmann::json envelope = {
        {"version", 1},
        {"connection_id", proxy.to_connection_ID()},
        {"attempt", args.attempt},
        {"event", args.event}
    };
    const nlohmann::json observation = {
        {"envelope", envelope},
        {"target", {args.cx->host(), std::stoi(args.cx->port())}},
        {"peername", socket_endpoint(args.cx, true)},
        {"sockname", socket_endpoint(args.cx, false)},
        {"client_peername", socket_endpoint(proxy.first_left(), true)},
        {"client_sockname", socket_endpoint(proxy.first_left(), false)},
        {"client_closed", !proxy.first_left() || proxy.first_left()->socket() <= 0},
        {"session_ending", args.session_ending},
        {"error", args.error}
    };

    // Transport observations are synchronous so content and CONNECT replies
    // cannot overtake them. An unavailable observer does not authorize traffic.
    // Native policy remains in charge; ordinary observer failure is fail-open.
    bool proceed = !proxy.webhook_control_->strict();
    sx::http::webhooks::send_action_wait(
        "server-lifecycle", proxy.to_connection_ID(), {{"server", observation}},
        [&](const sx::http::expected_reply& reply) {
            if(!reply || reply->response.first != 200) {
                return;
            }

            const auto body = nlohmann::json::parse(reply->response.second, nullptr, false);
            if(!body.is_object() || body.value("action", "") != "server-lifecycle" ||
               body.value("id", "") != proxy.to_connection_ID() ||
               !body.contains("envelope") || body["envelope"] != envelope) {
                return;
            }

            // Only a valid explicit veto can stop the pending attempt. Target
            // mutation requires the separate native routing/policy contract.
            if(body.contains("proceed") && body["proceed"].is_boolean()) {
                proceed = body["proceed"].get<bool>();
            }
        });

    return proceed;
}

nlohmann::json ProxyHooks::tls_details(const TlsArgs& args) {

    auto* tls = dynamic_cast<SSLCom*>(args.cx->com());
    auto* ssl = tls->get_SSL();
    nlohmann::json details = {
        {"sni", tls->get_sni().empty() ? nlohmann::json(nullptr) : nlohmann::json(tls->get_sni())},
        {"alpn_base64", nullptr},
        {"cipher", nullptr},
        {"tls_version", nullptr},
        {"certificates", nlohmann::json::array()},
        {"error", args.error}
    };

    // Negotiated values describe the accepted handshake, even if a later read
    // has already failed. Nothing here changes OpenSSL or transport state.
    if(args.established && ssl) {
        const auto alpn = tls->negotiated_alpn();
        // An accepted handshake without ALPN has an empty selection, not an
        // unknown value. Preserve that distinction in the public descriptor.
        details["alpn_base64"] = b64_encode_text(alpn);
        details["cipher"] = SSL_get_cipher_name(ssl);
        details["tls_version"] = SSL_get_version(ssl);
    }

    // OpenSSL includes the leaf in the client-side chain but not necessarily
    // in the server-side chain. Publish it once, followed by its issuers.
    if(ssl) {
        auto leaf = std::unique_ptr<X509, decltype(&X509_free)>(
            SSL_get_peer_certificate(ssl), X509_free);
        if(leaf) {
            details["certificates"].push_back(certificate_pem(leaf.get()));
        }

        const auto* chain = SSL_get_peer_cert_chain(ssl);
        for(int index = 0; chain && index < sk_X509_num(chain); ++index) {
            auto* certificate = sk_X509_value(chain, index);
            if(!leaf || X509_cmp(leaf.get(), certificate) != 0) {
                details["certificates"].push_back(certificate_pem(certificate));
            }
        }
    }

    return details;
}

bool ProxyHooks::tls(MitmProxy& proxy, const TlsArgs& args) {

    const nlohmann::json envelope = {
        {"version", 1},
        {"connection_id", proxy.to_connection_ID()},
        {"attempt", args.attempt},
        {"side", args.client ? "client" : "server"},
        {"event", args.established ? "established" : "failed"}
    };
    auto observation = tls_details(args);
    observation["envelope"] = envelope;

    return tls_exchange(proxy, observation);
}

bool ProxyHooks::tls_start_client(MitmProxy& proxy, const TlsClientStartArgs& args) {

    const nlohmann::json observation = {
        {"envelope", {{"version", 1}, {"connection_id", proxy.to_connection_ID()},
            {"attempt", args.attempt}, {"side", "client"}, {"event", "start"}}},
        {"sni", args.sni}
    };

    return tls_exchange(proxy, observation);
}

nlohmann::json ProxyHooks::quic(const QuicArgs& args) {

    nlohmann::json decision = {{"proceed", !args.strict}};
    const auto& envelope = args.observation.at("envelope");
    const auto wire = args.meta ? handshake_metadata(args.observation, true) : args.observation;

    sx::http::webhooks::send_action_wait(
        "quic-lifecycle", args.connection_id, {{"quic", wire}},
        [&](const sx::http::expected_reply& reply) {
            if(!reply || reply->response.first != 200) return;

            auto body = nlohmann::json::parse(reply->response.second, nullptr, false);
            if(args.meta && !decode_handshake_reply(body, envelope.at("event") == "start", true, true)) {
                return;
            }
            if(!body.is_object() || body.value("action", "") != "quic-lifecycle" ||
               body.value("id", "") != args.connection_id ||
               !body.contains("envelope") || body["envelope"] != envelope ||
               !body.contains("proceed") || !body["proceed"].is_boolean()) {
                return;
            }

            decision = std::move(body);
        });

    return decision;
}

bool ProxyHooks::tls_exchange(MitmProxy& proxy, const nlohmann::json& observation) {

    const auto& envelope = observation.at("envelope");
    const auto wire = proxy.webhook_tls_meta_ ? handshake_metadata(observation, false) : observation;

    // Preserve callback order before application events. As with server hooks,
    // observer unavailability is fail-open unless strict control was negotiated.
    bool proceed = !proxy.webhook_control_->strict();
    sx::http::webhooks::send_action_wait(
        "tls-lifecycle", proxy.to_connection_ID(), {{"tls", wire}},
        [&](const sx::http::expected_reply& reply) {
            if(!reply || reply->response.first != 200) {
                return;
            }

            auto body = nlohmann::json::parse(reply->response.second, nullptr, false);
            if(proxy.webhook_tls_meta_ &&
               !decode_handshake_reply(body, envelope.at("event") == "start", false, false)) {
                return;
            }
            if(!body.is_object() || body.value("action", "") != "tls-lifecycle" ||
               body.value("id", "") != proxy.to_connection_ID() ||
               !body.contains("envelope") || body["envelope"] != envelope) {
                return;
            }

            if(body.contains("proceed") && body["proceed"].is_boolean()) {
                proceed = body["proceed"].get<bool>();
            }
        });

    return proceed;
}

ProxyHooks::TlsOfferDecision ProxyHooks::client_hello(MitmProxy& proxy,
                                                         const ClientHelloArgs& args) {

    const nlohmann::json envelope = {
        {"version", 1},
        {"connection_id", proxy.to_connection_ID()},
        {"attempt", args.attempt},
        {"side", "client"},
        {"event", "client-hello"}
    };
    nlohmann::json observation = {
        {"envelope", envelope},
        {"client_hello_base64", b64_encode_text(args.body)},
        {"upstream", {
            {"sni", args.upstream_sni},
            {"alpn_base64", args.alpn_blocked || args.upstream_alpn.empty()
                ? std::string{} : b64_encode_text(args.upstream_alpn)},
            {"openssl_cipher_list", nullptr}
        }},
        {"upstream_alpn_blocked", args.alpn_blocked}
    };

    if(proxy.webhook_tls_clienthello_meta_) {
        // The public draft mirrors this structure. Encode each ALPN bytes
        // value separately; length-prefixing remains a native TLS detail.
        nlohmann::json offers = nlohmann::json::array();
        if(!args.alpn_blocked) {
            for(std::size_t offset = 0; offset < args.upstream_alpn.size();) {
                const auto length = static_cast<unsigned char>(args.upstream_alpn[offset++]);
                if(!length || offset + length > args.upstream_alpn.size()) {
                    throw std::runtime_error("Invalid native ClientHello ALPN offer");
                }
                offers.push_back(b64_encode_text(std::string(args.upstream_alpn.substr(offset, length))));
                offset += length;
            }
        }

        observation = {
            {"envelope", envelope}, {"schema", 2},
            {"client_hello", {
                {"original", {{"body_base64", b64_encode_text(args.body)}}},
                {"sni", args.upstream_sni}, {"alpn_offers", std::move(offers)},
                {"openssl_cipher_list", args.upstream_ciphers}, {"decision", "continue"}
            }}
        };
    }

    return tls_offer(proxy, args, observation);
}

ProxyHooks::TlsOfferDecision ProxyHooks::tls_start_server(MitmProxy& proxy,
                                                            const TlsStartArgs& args) {

    const nlohmann::json observation = {
        {"envelope", {{"version", 1}, {"connection_id", proxy.to_connection_ID()},
            {"attempt", args.attempt}, {"side", "server"}, {"event", "start"}}},
        {"upstream", {
            {"sni", args.upstream_sni},
            {"alpn_base64", args.alpn_blocked || args.upstream_alpn.empty()
                ? std::string{} : b64_encode_text(args.upstream_alpn)},
            {"openssl_cipher_list", args.upstream_ciphers}
        }}
    };

    ClientHelloArgs offer;
    offer.upstream_sni = args.upstream_sni;
    offer.upstream_alpn = args.upstream_alpn;
    offer.alpn_blocked = args.alpn_blocked;

    return tls_offer(proxy, offer, observation);
}

ProxyHooks::TlsOfferDecision ProxyHooks::tls_offer(MitmProxy& proxy,
                                                      const ClientHelloArgs& args,
                                                      const nlohmann::json& observation) {

    const auto& envelope = observation.at("envelope");
    const bool hello = envelope.at("event") == "client-hello";
    const bool meta_start = !hello && proxy.webhook_tls_meta_;
    const auto wire = meta_start ? handshake_metadata(observation, false) : observation;

    // A malformed or unavailable reply must never partially enable bypass.
    TlsOfferDecision decision;
    decision.proceed = !proxy.webhook_control_->strict();

    sx::http::webhooks::send_action_wait(
        "tls-lifecycle", proxy.to_connection_ID(), {{"tls", wire}},
        [&](const sx::http::expected_reply& reply) {
            if(!reply || reply->response.first != 200) {
                return;
            }

            auto body = nlohmann::json::parse(reply->response.second, nullptr, false);
            if(meta_start && !decode_handshake_reply(body, true, true, false)) {
                return;
            }
            if(hello && observation.value("schema", 1) == 2 && !decode_client_hello_reply(body)) {
                return;
            }

            if(!body.is_object() || body.value("action", "") != "tls-lifecycle" ||
               body.value("id", "") != proxy.to_connection_ID() ||
               !body.contains("envelope") || body["envelope"] != envelope ||
               !body.contains("proceed") || !body["proceed"].is_boolean() ||
               (hello && (!body.contains("ignore_connection") || !body["ignore_connection"].is_boolean()))) {
                return;
            }

            TlsOfferDecision candidate;
            candidate.proceed = body["proceed"].get<bool>();
            candidate.ignore_connection = hello && candidate.proceed && body["ignore_connection"].get<bool>();

            // Older receivers omit upstream settings. Validate a complete new
            // offer before publishing any part of the callback decision.
            if(body.contains("upstream") && candidate.proceed && !candidate.ignore_connection) {
                const auto& upstream = body["upstream"];
                if(!upstream.is_object() || !upstream.contains("sni") || !upstream["sni"].is_string() ||
                   !upstream.contains("alpn_base64") || !upstream["alpn_base64"].is_string()) {
                    return;
                }

                candidate.upstream_sni = upstream["sni"].get<std::string>();
                const auto encoded = upstream["alpn_base64"].get<std::string>();
                if(encoded.size() > 87380 ||
                   (candidate.upstream_sni != args.upstream_sni && !valid_upstream_sni(candidate.upstream_sni))) {
                    return;
                }

                candidate.upstream_alpn = b64_decode(encoded);
                const auto canonical = candidate.upstream_alpn.empty()
                    ? std::string{} : b64_encode_text(candidate.upstream_alpn);
                if(canonical != encoded || !alpn_subset(candidate.upstream_alpn, args.upstream_alpn) ||
                   (args.alpn_blocked && !candidate.upstream_alpn.empty())) {
                    return;
                }

                // The adapter supplies OpenSSL syntax, not addon cipher names.
                // Absence/null preserves native defaults for older receivers.
                if(upstream.contains("openssl_cipher_list") && !upstream["openssl_cipher_list"].is_null()) {
                    const auto& value = upstream["openssl_cipher_list"];
                    if(!value.is_string()) return;

                    const auto ciphers = value.get<std::string>();
                    if(ciphers.size() > 65535 || ciphers.find('\0') != std::string::npos) return;
                    candidate.upstream_cipher_list = ciphers;
                }

                // Echoing the prefilled expression is not an override. Keep
                // the default session-cache identity for an unchanged draft.
                if(hello && observation.value("schema", 1) == 2 &&
                   candidate.upstream_cipher_list == args.upstream_ciphers) {
                    candidate.upstream_cipher_list.reset();
                }

                const bool cipher_changed = hello
                    ? candidate.upstream_cipher_list.has_value()
                    : upstream.value("openssl_cipher_list", nlohmann::json(nullptr)) !=
                        observation.at("upstream").at("openssl_cipher_list");

                const auto current_alpn = args.alpn_blocked ? std::string_view{} : args.upstream_alpn;
                candidate.update_upstream = candidate.upstream_sni != args.upstream_sni ||
                                            candidate.upstream_alpn != current_alpn ||
                                            cipher_changed;
            }

            decision = std::move(candidate);
        });

    return decision;
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
                std::string_view(reinterpret_cast<const char *>(buffer.data()), buffer.size()),
                response_hook);
        } else {
            sx::helper_debug::emit(sx::helper_debug::Service::sift, 0, "skipped",
                                   "reason=payload-limit session=" +
                                       sx::helper_debug::field(proxy.to_connection_ID()) +
                                       " side=" + (right_side ? "R" : "L") +
                                       " sent=" + std::to_string(sent_bytes) +
                                       " limit=" + std::to_string(payload_limit));
        }
    }
    if (args.regular_webhook) {
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
