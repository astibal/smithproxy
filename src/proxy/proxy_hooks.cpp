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

} // namespace

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
                if (!reply) return;

                auto result = sx::proxy::parse_setup_reply(
                    reply->response.first, reply->response.second);
                proxy.webhook_control_->apply(result.body);

                using action = sx::proxy::setup_action;
                valid_reply = result.action != action::invalid;

                if (result.action == action::accept) {
                    proxy.webhook_rewrite_allowed_ = result.rewrite;
                    proxy.flow_ctx_->allow_rewrite(local_rewrite || result.rewrite);
                }

                if (result.action == action::drop) {
                    proxy.state().dead(true);
                } else if (result.action == action::not_interested) {
                    // Strict mode requires continued content delivery.
                    if (proxy.webhook_control_->strict()) valid_reply = false;
                    else proxy.webhook_content_wanted_ = false;
                }
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

bool ProxyHooks::content(MitmProxy& proxy, const ContentArgs& args) {
    auto* cx = args.cx;
    const auto side = args.side;
    auto& buffer = *args.data;
    const auto payload_layer = args.payload_layer;
    const bool regular_webhook = args.regular_webhook;
    const bool sift = args.sift;
    auto& reverse_output = *args.reverse_output;

    auto& log = proxy.log_content;

    bool was_modified = false;
    const bool reverse_allowed = proxy.webhook_rewrite_allowed_ && proxy.flow_ctx_->can_inject() &&
        proxy.left_sockets.size() + proxy.left_delayed_accepts.size() == 1 &&
        proxy.right_sockets.size() + proxy.right_delayed_accepts.size() == 1 &&
        cx->com()->l4_proto() == SOCK_STREAM;

    nlohmann::json j;
    auto cl = proxy.to_connection_label();
    j["info"] = {
        { "session", cl },
        { "side", string_format("%c", from_side(side)) },
        { "payload_layer", std::string(payload_layer) },
        { "L7_payload_start", nlohmann::json::array({-1}) },
        { "L7_payload_end", nlohmann::json::array({-1}) },
        { "L7_encoding", nlohmann::json::array({""}) },
        { "content_annotations", nlohmann::json::array() }
    };
    proxy.add_webhook_stream_details(j["info"]);
    if(regular_webhook) {
        // Advertise support before Spider may publish its first stateful rewrite.
        j["info"]["webhook_control"] = {
            {"version", 1}, {"mode", proxy.webhook_control_->strict() ? "strict" : "regular"},
            {"sequence", ++proxy.webhook_control_->content_sequence},
            {"rewrite", proxy.webhook_rewrite_allowed_},
            {"content-reverse", reverse_allowed}
        };
    }

    auto publish_l7_ranges = [&j](auto const& ranges,
                                  std::vector<std::string> const& known_encodings,
                                  auto const& annotations) {
        auto metadata = sx::proxy::l7_payload_metadata(ranges, known_encodings,
                                                       annotations);
        for(auto& [key, value] : metadata.items())
            j["info"][key] = std::move(value);
    };

    auto publish_matching_observation = [&](MitmHostCX const* context) {
        if(!context) return false;
        auto const app = std::dynamic_pointer_cast<HttpApplication>(
            context->engine().application_data);
        if(!app || !app->l7_payload_matches(buffer.string_view(),
                                             cx->meter_read_bytes)) return false;
        publish_l7_ranges(app->l7_payload, app->l7_encoding,
                          app->payload_annotations);
        return true;
    };
    // TCP HTTP/1 and HTTP/2 framing is owned by the connection FlowCtx. The
    // current side context may still contain an outer HTTP/1 CONNECT application;
    // consulting it first can therefore attach HTTP/1 annotations to inner
    // HTTP/2 bytes.  HTTP/3 is the exception: its transport adapter stores
    // observations on the current QUIC stream context.
    auto const* current = MitmHostCX::from_baseHostCX(cx);
    auto const current_app = current
        ? std::dynamic_pointer_cast<HttpApplication>(
              current->engine().application_data)
        : nullptr;
    if(current_app && current_app->version == HttpApplication::HTTP_VER::HTTP3) {
        publish_matching_observation(current);
    } else {
        publish_matching_observation(proxy.first_left());
    }

    if(auto* right = proxy.first_right(); right != nullptr) {
        if(auto* tls = dynamic_cast<SSLCom*>(right->com()); tls != nullptr) {
            if(auto const& sni = tls->get_sni(); !sni.empty()) {
                j["info"]["flow.tls.sni"] = sni;
            }
        }
    }

    if(auto const* left = proxy.first_left(); left != nullptr) {
        auto const app = std::dynamic_pointer_cast<sx::engine::http::app_HttpRequest>(
            left->engine().application_data);

        if(app && app->populated()) {
            auto const http2 = app->version == sx::engine::http::app_HttpRequest::HTTP_VER::HTTP2;
            auto const http3 = app->version == sx::engine::http::app_HttpRequest::HTTP_VER::HTTP3;
            auto const prefix = http3 ? "flow.http3." :
                                http2 ? "flow.http2." : "flow.http1.";

            j["info"][http3 ? "flow.http3" : http2 ? "flow.http2" : "flow.http1"] = true;

            auto put = [&](std::string const& field, std::string const& value) {
                if(!value.empty()) j["info"][prefix + field] = value;
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
    }

    bool content_reply_received = false;
    auto response_hook = [&, sift](sx::http::expected_reply r){
        if(r.has_value()) {
            auto reply = r.value();
            _dia("webhook content-replace: response %d", reply.response.first);

            if(reply.response.first >= 200 and reply.response.first < 300) {
                auto json_obj = nlohmann::json::parse(reply.response.second, nullptr, false);
                if(!json_obj.is_object()) {
                    _err("MitmProxy::content_webhook: response body is invalid");
                }
                else {
                    if(regular_webhook) {
                        proxy.webhook_control_->apply(json_obj);
                        content_reply_received = true;
                    }
                    if(sift) {
                        if(proxy.apply_sift_reply(json_obj)) proxy.publish_sift_classifications();
                    }
                    if(json_obj.contains("content-reverse")) {
                        try {
                            if(!regular_webhook || sift || !reverse_allowed) {
                                throw std::logic_error("Reverse content requires advertised rewrite views");
                            }

                            auto output = sx::proxy::DirectionalContent::parse(json_obj);
                            // Stage only. The proxy publishes input metadata and
                            // completes filtering before touching the reverse view.
                            reverse_output.assign(output.reverse.data(), output.reverse.size());
                            buffer.assign(output.forward.data(), output.forward.size());
                            was_modified = true;
                        }
                        catch(std::exception const& error) {
                            _err("Invalid directional webhook output: %s", error.what());
                            reverse_output.clear();
                            proxy.state().dead(true);
                        }
                        return;
                    }
                    if(json_obj.contains("action")) {
                        const auto& action = json_obj["action"];
                        const bool changes_stream = action == "replace" || action == "discard" ||
                            action == "need-more" || json_obj.contains("content");

                        if (action == "drop") {
                            proxy.state().dead(true);
                            return;
                        }

                        std::optional<std::string> replacement;
                        const auto content = json_obj.find("content");

                        if (content != json_obj.end() && content->is_string()) {
                            replacement = b64_decode(content->get_ref<const std::string&>());
                        }

                        // Same-size replace is an intentional low-level escape
                        // hatch, not a claim of protocol safety. Keep the input
                        // context as-is: the script owns any resulting mismatch.
                        // Compare decoded bytes, not the base64 envelope size.
                        const bool same_size_replace = action == "replace" && replacement &&
                            replacement->size() == buffer.size();

                        if (changes_stream && (sift || (!proxy.webhook_rewrite_allowed_ && !same_size_replace))) {
                            _err("content mutation requires setup rewrite permission or a same-size replace");
                            proxy.state().dead(true);
                            return;
                        }

                        if(regular_webhook && json_obj["action"] == "not-interested" &&
                           !proxy.webhook_control_->strict()) {
                            proxy.webhook_content_wanted_ = false;
                            _dia("webhook content: peer declined future content for this connection");
                        }
                        else if(json_obj["action"] == "discard") {
                            // data sent to webhook shall be discarded
                            buffer.size(0);
                            was_modified = true;
                        }
                        else if(regular_webhook && json_obj["action"] == "need-more") {
                            // The webhook owns these bytes now: consume this chunk
                            // without forwarding it or retaining another copy here.
                            // Keep future content callbacks enabled. The webhook may
                            // return the accumulated content with a later replacement.
                            buffer.size(0);
                            was_modified = true;
                            _dia("webhook content: chunk consumed; awaiting more content");
                        }
                        else {
                            // catch-all code to decode response if present
                            if(replacement) {
                                const auto& decoded = *replacement;

                                _dia("webhook content-replace: received %dB of replacement data", decoded.size());
                                {
                                    auto& log = proxy.log_content_dump;
                                    _deb("webhook content-replace: replacement: %s\r\n",
                                         hex_dump((unsigned char*)decoded.data(), decoded.size(), 4, 0, true).c_str());
                                }

                                buffer.assign(decoded.data(), decoded.size());
                                was_modified = true;
                            }
                            else {
                                _dia("webhook content-replace: no replacement body received");
                            }
                        }
                    }
                }
            }
            else if(sift) {
                auto json_obj = nlohmann::json::parse(
                    reply.response.second, nullptr, false);
                if(!json_obj.is_discarded() && proxy.apply_sift_reply(json_obj))
                    proxy.publish_sift_classifications();
            }
        }
    };
    if(sift) {
        const bool right_side = side == side_t::RIGHT;
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
    if(regular_webhook) {
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
    if(regular_webhook && !content_reply_received && proxy.webhook_control_->strict()) {
        buffer.size(0);
        proxy.state().dead(true);
        return true;
    }

    return was_modified;
}

} // namespace sx::proxy
