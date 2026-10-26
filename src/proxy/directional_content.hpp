#pragma once

#include <common/base64.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace sx::proxy {

struct DirectionalContent {
    std::string forward;
    std::string reverse;

    static constexpr std::size_t max_bytes = 1024 * 1024;

    // Validate both outputs before changing any buffer. The new contract uses
    // canonical padded base64, and bounds allocation before invoking the codec.
    static std::string decode(nlohmann::json const& value) {
        if(!value.is_string()) throw std::invalid_argument("Content must be a base64 string");

        auto const& text = value.get_ref<std::string const&>();

        if(text.empty()) return {};

        if(text.size() > ((max_bytes + 2) / 3) * 4 || text.size() % 4 != 0) {
            throw std::invalid_argument("Invalid content size or base64 length");
        }

        const auto padding = text.back() == '=' ? (text[text.size() - 2] == '=' ? 2U : 1U) : 0U;

        for(std::size_t index = 0; index < text.size() - padding; ++index) {
            const auto ch = text[index];

            if(!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                 (ch >= '0' && ch <= '9') || ch == '+' || ch == '/')) {
                throw std::invalid_argument("Invalid base64 character");
            }
        }

        auto decoded = libbase64::decode<std::string, char, unsigned char, false>(text);
        const auto canonical = libbase64::encode<std::string, char, unsigned char, true>(
            reinterpret_cast<unsigned char const*>(decoded.data()), decoded.size());

        if(decoded.size() > max_bytes || canonical != text) {
            throw std::invalid_argument("Noncanonical or oversized content");
        }

        return decoded;
    }

    static DirectionalContent parse(nlohmann::json const& reply) {
        if(reply.value("action", nlohmann::json()) != "replace" ||
           !reply.contains("content") || !reply.contains("content-reverse")) {
            throw std::invalid_argument("Reverse content requires replace and both content fields");
        }

        DirectionalContent output{decode(reply.at("content")), decode(reply.at("content-reverse"))};

        if(output.forward.size() + output.reverse.size() > max_bytes) {
            throw std::invalid_argument("Directional content exceeds 1 MiB combined");
        }

        return output;
    }
};

} // namespace sx::proxy
