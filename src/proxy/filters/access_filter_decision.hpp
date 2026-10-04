#pragma once

#include <nlohmann/json.hpp>

#include <string_view>

namespace sx::proxy {

enum class access_decision {
    fail_open_transport,
    fail_open_invalid_response,
    accept,
    reject,
};

struct access_decision_result {
    access_decision decision = access_decision::fail_open_transport;
    nlohmann::json response;
};

inline access_decision_result parse_access_response(long code, std::string_view body) {
    if (code < 200 || code >= 300) {
        return {};
    }

    auto response = nlohmann::json::parse(body.begin(), body.end(), nullptr, false);
    if (!response.is_object()) {
        return {access_decision::fail_open_invalid_response, std::move(response)};
    }

    auto value = response.find("access-response");
    if (value == response.end() || !value->is_string()) {
        return {access_decision::fail_open_invalid_response, std::move(response)};
    }

    auto const& decision = value->get_ref<std::string const&>();
    if (decision == "accept") {
        return {access_decision::accept, std::move(response)};
    }
    if (decision == "reject") {
        return {access_decision::reject, std::move(response)};
    }
    return {access_decision::fail_open_invalid_response, std::move(response)};
}

} // namespace sx::proxy
