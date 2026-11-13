#pragma once

#include <service/http/async_request.hpp>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>

namespace sx::http::webhooks {

inline std::string format_sift_service_diagnostics(expected_reply const& reply, bool lored_only = false) {
    const std::string heading = lored_only
        ? "\nLoreD via Sift (whole Sift instance):\n"
        : "\nSift service diagnostics (whole Sift instance):\n";
    if(!reply) return heading + "  unavailable: no response";
    const auto& [status, body] = reply->response;
    if(status < 200 || status >= 300)
        return heading + "  unavailable: HTTP/transport status " + std::to_string(status) +
            "\n  error: " + nlohmann::json(body).dump();
    const auto data = nlohmann::json::parse(body, nullptr, false);
    if(!data.is_object()) return heading + "  unavailable: invalid diagnostics JSON";

    std::ostringstream output;
    output << heading;
    // Keep every returned field, including counters added by newer Sift versions.
    for(auto const* section : {"lored", "http", "engine", "dns_evidence"}) {
        if((std::string_view(section) == "lored") != lored_only) continue;
        output << "  --- " << (std::string_view(section) == "lored" ? "LoreD" : section)
               << " ---\n";
        const auto found = data.find(section);
        if(found == data.end() || !found->is_object()) {
            output << "    unavailable: section missing or invalid\n";
            continue;
        }
        // JSON escaping prevents remote strings from injecting terminal controls.
        std::istringstream lines(found->dump(2));
        for(std::string line; std::getline(lines, line);) output << "    " << line << '\n';
    }
    for(auto const& [key, value] : data.items()) {
        if(key != "lored" && key != "http" && key != "engine" && key != "dns_evidence")
            output << "  " << nlohmann::json(key).dump() << ": " << value.dump() << '\n';
    }
    return output.str();
}

inline std::string fetch_sift_service_diagnostics(AsyncRequest::request_settings const& settings, bool lored_only = false) {
    if(!settings.enabled)
        return "\nSift service diagnostics: unavailable (Sift disabled in Smithproxy)";
    if(settings.url.empty())
        return "\nSift service diagnostics: unavailable (Sift endpoint not configured)";
    try {
        auto url = settings.url;
        const auto scheme = url.find("://");
        const auto authority = scheme == std::string::npos ? 0 : scheme + 3;
        const auto path = url.find_first_of("/?#", authority);
        url.erase(path == std::string::npos ? url.size() : path);
        url += "/api/diagnostics";
        Request request(Request::DEFAULT, settings.dns_servers);
        request.set_helper_diagnostics(settings.service, settings.exchange_id);
        request.set_timeout(3);
        request.set_max_response_size(1024 * 1024);
        if(!settings.verify_tls) request.disable_tls_verify();
        if(!settings.unix_socket_path.empty()) {
            if(!request.set_unix_socket_path(settings.unix_socket_path))
                return "\nSift service diagnostics: unavailable (cannot configure Unix transport)";
        } else if(!settings.bind_interface.empty()) request.set_interface(settings.bind_interface);
        return format_sift_service_diagnostics(request.emit(url, {}, Request::Method::get), lored_only);
    } catch(std::exception const& error) {
        return "\nSift service diagnostics: unavailable: " + nlohmann::json(error.what()).dump();
    }
}

} // namespace sx::http::webhooks
