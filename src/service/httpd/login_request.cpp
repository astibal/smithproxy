#include "login_request.hpp"

#include <algorithm>
#include <map>
#include <utility>

namespace sx::webserver {
namespace {

constexpr std::size_t maximum_username_bytes = 256U;
constexpr std::size_t maximum_password_bytes = 1024U;

std::optional<unsigned char> hex_nibble(char character) {
    if(character >= '0' && character <= '9')
        return static_cast<unsigned char>(character - '0');
    if(character >= 'a' && character <= 'f')
        return static_cast<unsigned char>(character - 'a' + 10);
    if(character >= 'A' && character <= 'F')
        return static_cast<unsigned char>(character - 'A' + 10);
    return std::nullopt;
}

std::optional<std::string> decode_component(std::string_view encoded) {
    std::string decoded;
    decoded.reserve(encoded.size());
    for(std::size_t index = 0; index < encoded.size(); ++index) {
        const auto character = encoded[index];
        if(character == '+') {
            decoded.push_back(' ');
            continue;
        }
        if(character != '%') {
            if(character == '\0') return std::nullopt;
            decoded.push_back(character);
            continue;
        }
        if(index + 2U >= encoded.size()) return std::nullopt;
        const auto high = hex_nibble(encoded[index + 1U]);
        const auto low = hex_nibble(encoded[index + 2U]);
        if(!high || !low) return std::nullopt;
        const auto byte = static_cast<unsigned char>((*high << 4U) | *low);
        if(byte == 0U) return std::nullopt;
        decoded.push_back(static_cast<char>(byte));
        index += 2U;
    }
    return decoded;
}

bool safe_username(std::string_view username) {
    const bool valid_size = !username.empty() &&
        username.size() <= maximum_username_bytes;
    const bool printable = valid_size &&
        std::all_of(username.begin(), username.end(), [](const unsigned char byte) {
            return byte >= 0x20U && byte != 0x7fU;
        });
    return printable;
}

bool safe_password(std::string_view password) {
    return !password.empty() && password.size() <= maximum_password_bytes;
}

}  // namespace

LoginRequestResult parse_login_request(std::string_view body) {
    std::map<std::string, std::string> fields;
    std::size_t start = 0;
    while(start <= body.size()) {
        const auto end = body.find('&', start);
        const auto field = body.substr(
            start, end == std::string_view::npos ? body.size() - start : end - start);
        const auto separator = field.find('=');
        if(separator == std::string_view::npos)
            return {std::nullopt, "login fields must use name=value form"};

        auto name = decode_component(field.substr(0, separator));
        auto value = decode_component(field.substr(separator + 1U));
        if(!name || !value)
            return {std::nullopt, "login form contains invalid percent encoding"};
        const bool recognized = *name == "username" || *name == "password";
        if(!recognized)
            return {std::nullopt, "login form contains an unsupported field"};
        if(!fields.emplace(std::move(*name), std::move(*value)).second)
            return {std::nullopt, "login form contains a duplicate field"};

        if(end == std::string_view::npos) break;
        start = end + 1U;
    }

    const auto username = fields.find("username");
    const auto password = fields.find("password");
    const bool complete = username != fields.end() && password != fields.end();
    if(!complete) return {std::nullopt, "login requires username and password"};
    if(!safe_username(username->second))
        return {std::nullopt, "login username is invalid"};
    if(!safe_password(password->second))
        return {std::nullopt, "login password is invalid"};
    return {LoginRequest{username->second, password->second}, {}};
}

}  // namespace sx::webserver
