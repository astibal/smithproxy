#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <functional>
#include <sys/socket.h>
#include <openssl/ssl.h>

namespace sx::proxymaker { class SessionSetup; }

namespace sx::quic {

// Values belong to one forwarding handshake, never the certificate probe.
struct HookEvent {
    enum class Kind { start, established, failed };
    Kind kind = Kind::start;
    bool client = false;
    std::string sni;
    std::string alpn;
    std::optional<std::string> ciphers;
    std::string cipher;
    std::string error;
    std::vector<std::string> certificates;
};

// Install before workers start. Calls are synchronous on the session owner;
// callbacks must not retain the setup or event, reenter transport I/O, or throw.
struct Hooks {
    using Callback = bool (*)(proxymaker::SessionSetup&, HookEvent&) noexcept;
    Callback handshake = nullptr;

    static Hooks& registry() {
        static Hooks hooks;
        return hooks;
    }
};

class openssl_connection;

// Apply the hook offer, then configure the upstream SSL before it sends an
// Initial. A rejected hook/configuration returns null and reports the error.
std::unique_ptr<openssl_connection> connect_with_hooks(
    SSL_CTX* context, const sockaddr* peer, socklen_t size,
    const std::string& server_name, std::string* error, proxymaker::SessionSetup* setup,
    std::function<bool(SSL*)> const& configure = {}, SSL* port = nullptr);

// Report a failed transport allocation/configuration before a live TLS object exists.
bool hook_failure(proxymaker::SessionSetup*, std::string const& name, std::string const& error);

bool apply_hook_offer(SSL* ssl, const HookEvent& offer, const std::string& identity);

bool hook_start(proxymaker::SessionSetup* setup, HookEvent& event);
bool hook_outcome(proxymaker::SessionSetup* setup, SSL* ssl, bool client,
                  const char* failure = nullptr);

} // namespace sx::quic
