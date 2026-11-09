#pragma once

#include <cstdint>
#include <string_view>
#include <optional>
#include <nlohmann/json.hpp>
#include <vars.hpp>
#include <service/auth/pap.hpp>

class MitmProxy;
class baseHostCX;
class buffer;

namespace sx::proxy {

// Executes proxy hooks and applies their decisions synchronously where required.
// The proxy owns lifetime and call ordering; asynchronous replies retain only
// shared webhook control, never a reference to the proxy itself.
class ProxyHooks {
public:
    // Hooks without additional inputs still use the same explicit call shape.
    struct StartDetailsArgs {};
    struct StartArgs {};
    struct QuicArgs {
        bool meta = false;
        std::string connection_id;
        bool strict = false;
        nlohmann::json observation;
    };
    static nlohmann::json quic(const QuicArgs& args);
    // Owned snapshots only: no proxy/CX references survive transport teardown.
    struct Epitaph {
        std::string connection_id;
        nlohmann::json details;
        nlohmann::json filter_info;
    };
    struct StopArgs {};

    struct ReadinessArgs {
        unsigned char side = 0;
        baseHostCX* cx = nullptr;
        const char* event = nullptr;
        std::uint64_t attempt = 0;
    };

    // Borrowed inputs, valid throughout the synchronous call. The caller must
    // supply cx and both buffers; no ownership is transferred to the hook.
    struct ContentArgs {
        baseHostCX* cx = nullptr;
        socle::side_t side = socle::side_t::LEFT;
        buffer* data = nullptr;
        std::string_view payload_layer;
        bool regular_webhook = false;
        bool sift = false;
        buffer* reverse_output = nullptr;
    };

    // Authentication runs on the frontend before target setup. Inputs are
    // borrowed only for this synchronous veto; AAA remains authoritative.
    struct AuthenticationArgs {
        std::string protocol;
        sx::auth::PapCredentials credentials;
        sx::auth::Result baseline;
        nlohmann::json protocol_context = nullptr;
    };

    static sx::auth::Result authentication(const baseHostCX& client,
                                          const AuthenticationArgs& args);

    struct ServerArgs {
        baseHostCX* cx = nullptr;
        std::string_view event;
        std::uint64_t attempt = 0;
        std::string_view error;
        bool session_ending = false;
    };

    static bool server(MitmProxy& proxy, const ServerArgs& args);

    struct TlsArgs {
        baseHostCX* cx = nullptr;
        bool client = false;
        bool established = false;
        std::uint64_t attempt = 0;
        std::string_view error;
    };

    static bool tls(MitmProxy& proxy, const TlsArgs& args);

    struct TlsStartArgs {
        std::uint64_t attempt = 0;
        std::string_view upstream_sni;
        std::string_view upstream_alpn;
        std::string_view upstream_ciphers;
        bool alpn_blocked = false;
    };

    struct TlsClientStartArgs {
        std::uint64_t attempt = 0;
        std::string_view sni;
    };

    static bool tls_start_client(MitmProxy& proxy, const TlsClientStartArgs& args);

    struct ClientHelloArgs {
        std::uint64_t attempt = 0;
        std::string_view body;
        std::string_view upstream_sni;
        std::string_view upstream_alpn;
        std::string_view upstream_ciphers;
        bool alpn_blocked = false;
    };
    struct TlsOfferDecision {
        bool proceed = true;
        bool ignore_connection = false;
        bool update_upstream = false;
        std::string upstream_sni;
        std::string upstream_alpn;
        std::optional<std::string> upstream_cipher_list;
    };

    static TlsOfferDecision client_hello(MitmProxy& proxy, const ClientHelloArgs& args);
    static TlsOfferDecision tls_start_server(MitmProxy& proxy, const TlsStartArgs& args);

private:
    static bool tls_exchange(MitmProxy& proxy, const nlohmann::json& observation);

    static TlsOfferDecision tls_offer(MitmProxy& proxy, const ClientHelloArgs& args,
                                         const nlohmann::json& observation);

public:


    struct HttpConnectArgs {
        std::string_view event;
        std::string_view request;
        std::string_view host;
        unsigned short port = 0;
        std::string_view response;
        bool authenticated = false;
        baseHostCX* client = nullptr;
        baseHostCX* server = nullptr;
    };

    struct HttpConnectDecision {
        enum class Action { unavailable, proceed, local_response, send_response, kill };
        Action action = Action::unavailable;
        std::string host;
        unsigned short port = 0;
        std::string response;
    };

    static HttpConnectDecision http_connect(MitmProxy& proxy, const HttpConnectArgs& args);

    static nlohmann::json start_details(const MitmProxy& proxy, const StartDetailsArgs& args);
    static bool start(MitmProxy& proxy, const StartArgs& args);
    static Epitaph prepare_stop(const MitmProxy& proxy, const StopArgs& args);
    static void stop(const Epitaph& epitaph, const StopArgs& args);
    static void readiness(const MitmProxy& proxy, const ReadinessArgs& args);
    static bool content(MitmProxy& proxy, const ContentArgs& args);

private:
    // Internal arguments keep per-call state out of the proxy and out of
    // asynchronous callbacks. Their definitions belong to the implementation.
    struct HttpConnectReplyArgs;
    struct StartReplyArgs;
    struct ContentExchangeArgs;
    struct ContentReplyArgs;
    struct ContentActionArgs;

    static nlohmann::json tls_details(const TlsArgs& args);
    static nlohmann::json http_connect_details(const MitmProxy& proxy, const HttpConnectArgs& args);
    static void http_connect_reply(MitmProxy& proxy, const HttpConnectReplyArgs& args);

    static bool start_reply(MitmProxy& proxy, const StartReplyArgs& args);
    static nlohmann::json content_details(MitmProxy& proxy, const ContentExchangeArgs& args);
    static void content_reply(MitmProxy& proxy, const ContentReplyArgs& args);
    static void content_action(MitmProxy& proxy, const ContentActionArgs& args);
    static void content_reverse(MitmProxy& proxy, const ContentActionArgs& args);

};

} // namespace sx::proxy
