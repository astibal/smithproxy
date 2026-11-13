#include <inspect/http_diagnostics.hpp>
#include <inspect/engine/http3.hpp>
#include <inspect/engine/http3_adapter.hpp>

namespace sx::engine::http {
namespace {

using nlohmann::json;
using Endpoint = ProtocolEndpoint;

json request(app_HttpRequest::HttpData const& data) {
    json result = json::object();
    auto put = [&](char const* key, std::string const& value) {
        if (!value.empty()) result[key] = value;
    };
    put("method", data.method);
    put("host", data.host);
    put("path", data.uri);
    put("query", data.params);
    put("referer", data.referer);
    put("content_type", data.content_type);
    put("accept", data.accept);
    put("ja4h", data.ja4h);
    put("subprotocol", data.sub_proto);
    auto url = data.proto + data.host + data.uri;
    if (!data.params.empty()) url += "?" + data.params;
    put("url", url);
    return result;
}

json application(app_HttpRequest const& app) {
    json history = json::array();
    for (auto const& entry : app.http_history) history.push_back(request(entry));
    return {{"current", request(app.http_data)}, {"history", std::move(history)}};
}

json headers(v2::Http2Stream::value_list_t const& fields) {
    // H2 retains values grouped by name, not original wire order or sections.
    json result = json::array();
    for (auto const& [name, values] : fields) {
        for (auto const& value : values) result.push_back({name, value});
    }
    return result;
}

json h2_direction(v2::Http2Stream const& stream, bool client) {
    json result = {
        {"headers", headers(client ? stream.request_headers_ : stream.response_headers_)},
        {"ended", client ? stream.request_ended_ : stream.response_ended_},
        {"invalid", client ? stream.request_invalid_ : stream.response_invalid_},
        {"body_bytes", client ? stream.request_body_bytes_ : stream.response_body_bytes_},
        {"flow_window", client ? stream.request_flow_window_ : stream.response_flow_window_}
    };
    auto length = client ? stream.request_content_length_ : stream.response_content_length_;
    if (length) result["content_length"] = *length;
    return result;
}

json h3_direction(v3::Http3Stream::Direction const& direction) {
    json sections = json::array();
    for (auto const& block : direction.headers) {
        json fields = json::array();
        for (auto const& field : block) fields.push_back({field.name, field.value});
        sections.push_back(std::move(fields));
    }
    json result = {{"header_sections", std::move(sections)},
                   {"ended", direction.finished}, {"final_headers", direction.final_headers}};
    if (direction.stream_type) result["stream_type"] = *direction.stream_type;
    if (direction.reset_error) result["reset_error"] = *direction.reset_error;
    if (!direction.metadata_limit.empty()) result["metadata_limit"] = direction.metadata_limit;
    return result;
}

json context(EngineCtx const& ctx, std::optional<ProtocolStream> key) {
    if (auto const* h3 = std::any_cast<v3::Http3Connection>(&ctx.state_data)) {
        // Read the child directly: application_data may currently point at a
        // different stream selected by the most recent transport callback.
        json result = {{"protocol", "http3"}, {"streams", json::array()}};
        if (!key) return result;
        auto found = h3->streams.find(*key);
        if (found == h3->streams.end()) return result;
        auto const& stream = found->second;
        if (stream.application) result.update(application(*stream.application));
        json detail = {{"id", key->id},
                       {"kind", (key->id & 2U) ? "unidirectional" : "request"},
                       {"request", h3_direction(stream.directions[0])},
                       {"response", h3_direction(stream.directions[1])}};
        detail["request"]["decode"] = v3::metadata(ctx, key->id, Endpoint::Client)["flow.http3.decode"];
        detail["response"]["decode"] = v3::metadata(ctx, key->id, Endpoint::Server)["flow.http3.decode"];
        result["streams"].push_back(std::move(detail));
        return result;
    }

    auto const* app = dynamic_cast<app_HttpRequest const*>(ctx.application_data.get());
    json result = app ? application(*app) : json::object();
    if (auto const* h2 = std::any_cast<v2::Http2Connection>(&ctx.state_data)) {
        result["protocol"] = "http2";
        result["connection_invalid"] = h2->connection_invalid;
        result["latest_request_stream_id"] = h2->latest_request_stream_id;
        result["streams"] = json::array();
        for (auto const& [id, stream] : h2->streams) {
            result["streams"].push_back({{"id", id},
                {"request", h2_direction(stream, true)},
                {"response", h2_direction(stream, false)}});
        }
    } else if (app) {
        result["protocol"] = app->http_str(app->version);
    }
    return result;
}

} // namespace

nlohmann::json diagnostics(ProtocolViews const& views, std::optional<ProtocolStream> stream) {
    auto client = context(views.context(Endpoint::Client), stream);
    if (client.empty()) return {};
    json result = {{"protocol", client.at("protocol")}, {"split", views.split()},
                   {"views", json::object()}};
    result["views"][views.split() ? "client" : "shared"] = std::move(client);
    if (views.split()) result["views"]["server"] = context(views.context(Endpoint::Server), stream);
    if (!views.fork_error().empty()) result["fork_error"] = views.fork_error();
    // HTTP field bytes are not necessarily UTF-8. Reuse the existing lossless
    // metadata encoding rather than letting a diagnostic break JSON output.
    v3::encode_metadata_bytes(result);
    return result;
}

} // namespace sx::engine::http
