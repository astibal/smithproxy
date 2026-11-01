#include "broker_client.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <sys/un.h>

namespace sx::auth {
namespace {
std::unique_ptr<BrokerPapBackend> proxy_backend;
constexpr std::size_t max_reply = 16384;

std::size_t receive_reply(char* data, std::size_t size, std::size_t count, void* context) {
    auto& reply = *static_cast<std::string*>(context);
    if(size != 1 || count > max_reply - reply.size()) {
        return 0;
    }
    reply.append(data, count);
    return count;
}

PapResult unavailable() {
    return {PapStatus::error, {}, "authentication broker unavailable or invalid"};
}
}

BrokerPapBackend::BrokerPapBackend(std::string socket_path, long timeout_ms)
    : socket_path_(std::move(socket_path)), timeout_ms_(timeout_ms) {
    if(socket_path_.empty() || socket_path_.front() != '/' ||
       socket_path_.size() >= sizeof(sockaddr_un::sun_path) ||
       socket_path_.find('\0') != std::string::npos || timeout_ms_ < 1 || timeout_ms_ > 10000) {
        throw std::invalid_argument("invalid authentication socket path or timeout");
    }
    static const auto initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(initialized != CURLE_OK) {
        throw std::runtime_error("cannot initialize authentication transport");
    }
}

std::optional<PapResult> BrokerPapBackend::verify_pap(
        PapCredentials credentials, completion_type) {
    if(credentials.username.empty() || credentials.username.size() > 255 ||
       credentials.password.empty() || credentials.password.size() > 1024) {
        return PapResult{PapStatus::rejected, {}, {}};
    }

    // The URL supplies HTTP framing only. curl must use this Unix socket and
    // must never consult an environment proxy or follow a redirect elsewhere.
    std::string body;
    try {
        body = nlohmann::json{{"version", 1}, {"username", credentials.username},
                              {"password", credentials.password}}.dump();
    } catch(...) {
        return PapResult{PapStatus::rejected, {}, {}};
    }
    auto handle = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(), curl_easy_cleanup);
    if(!handle) {
        return unavailable();
    }
    auto headers = std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)>(
        curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);
    if(!headers) {
        return unavailable();
    }

    std::string reply;
    if(curl_easy_setopt(handle.get(), CURLOPT_URL, "http://localhost/v1/pap") != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_UNIX_SOCKET_PATH, socket_path_.c_str()) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_PROXY, "") != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_CONNECTTIMEOUT_MS, timeout_ms_) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT_MS, timeout_ms_) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_HTTPHEADER, headers.get()) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDS, body.data()) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size())) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, receive_reply) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &reply) != CURLE_OK) {
        return unavailable();
    }
    const auto status = curl_easy_perform(handle.get());
    long http_status = 0;
    curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &http_status);
    if(status != CURLE_OK || http_status != 200) {
        return unavailable();
    }

    try {
        const auto value = nlohmann::json::parse(reply);
        if(!value.is_object() || value.at("version") != 1) {
            return unavailable();
        }
        const auto decision = value.at("status").get<std::string>();
        if(decision == "rejected") {
            return PapResult{PapStatus::rejected, {}, {}};
        }
        if(decision != "accepted") {
            return unavailable();
        }
        PapResult result{PapStatus::accepted, value.at("identity").get<std::string>(), {}};
        result.groups = value.at("groups").get<std::vector<std::string>>();
        if(result.identity.empty() || result.identity.size() > 512 || result.groups.size() > 64) {
            return unavailable();
        }
        for(const auto& group : result.groups) {
            if(group.empty() || group.size() > 255) {
                return unavailable();
            }
        }
        return result;
    } catch(...) {
        return unavailable();
    }
}

void configure_proxy_auth(std::string socket_path) {
    proxy_backend = std::make_unique<BrokerPapBackend>(std::move(socket_path));
}

bool proxy_auth_required() {
    return proxy_backend != nullptr;
}

PapResult verify_proxy_credentials(std::string_view username, std::string_view password) {
    if(!proxy_backend) {
        return unavailable();
    }
    auto result = proxy_backend->verify_pap({std::string(username), std::string(password)}, {});
    return result.value_or(unavailable());
}

std::optional<PapCredentials> http_basic_credentials(std::string_view headers) {
    std::string_view encoded;
    bool found = false;
    auto offset = headers.find("\r\n");
    if(offset == std::string_view::npos) {
        return std::nullopt;
    }
    offset += 2;
    while(offset < headers.size()) {
        const auto end = headers.find("\r\n", offset);
        if(end == std::string_view::npos || end == offset) {
            break;
        }
        const auto line = headers.substr(offset, end - offset);
        const auto colon = line.find(':');
        if(colon == std::string_view::npos || line.front() == ' ' || line.front() == '\t') {
            return std::nullopt;
        }
        std::string name(line.substr(0, colon));
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });
        if(name == "proxy-authorization") {
            if(found) {
                return std::nullopt;
            }
            found = true;
            auto value = line.substr(colon + 1);
            while(!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
                value.remove_prefix(1);
            }
            if(value.size() < 6) {
                return std::nullopt;
            }
            std::string scheme(value.substr(0, 6));
            std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char c) { return std::tolower(c); });
            if(scheme != "basic ") {
                return std::nullopt;
            }
            encoded = value.substr(6);
            while(!encoded.empty() && (encoded.back() == ' ' || encoded.back() == '\t')) {
                encoded.remove_suffix(1);
            }
        }
        offset = end + 2;
    }
    if(!found || encoded.empty() || encoded.size() > 1720 || encoded.size() % 4 != 0) {
        return std::nullopt;
    }

    // Decode a bounded, canonical Base64 value without another dependency.
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    unsigned bits = 0;
    unsigned count = 0;
    std::size_t padding = 0;
    for(char c : encoded) {
        if(c == '=') {
            ++padding;
            continue;
        }
        const auto digit = alphabet.find(c);
        if(padding != 0 || digit == std::string_view::npos) {
            return std::nullopt;
        }
        bits = (bits << 6) | static_cast<unsigned>(digit);
        count += 6;
        if(count >= 8) {
            count -= 8;
            decoded.push_back(static_cast<char>((bits >> count) & 255));
        }
    }
    if(padding > 2 || count != padding * 2 || (count && (bits & ((1U << count) - 1U)))) {
        return std::nullopt;
    }
    const auto colon = decoded.find(':');
    if(colon == std::string::npos || colon == 0 || colon > 255 ||
       decoded.size() - colon - 1 > 1024 || decoded.find('\0') != std::string::npos) {
        return std::nullopt;
    }
    return PapCredentials{decoded.substr(0, colon), decoded.substr(colon + 1)};
}
} // namespace sx::auth
