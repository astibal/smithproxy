#include <gtest/gtest.h>

#include <proxy/mitmproxy_utils.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/proxymaker_utils.hpp>
#include <staticcontent.hpp>

#include <openssl/x509v3.h>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include <map>
#include <memory>
#include <atomic>
#include <thread>
#include <vector>

TEST(MitmProxyReplacement, IsSelfContainedBrandedAndEscapesTheTarget) {
    std::string messages = "etc/msg/en/";
    ASSERT_TRUE(html()->load_files(messages));

    const auto target = sx::mitmproxy::html_escape(
        "https://unsafe.example/<script>");
    const auto page = html()->render_tls_replacement(
        target,
        "<section class=\"reason\"><p>Unknown issuer.</p></section>",
        R"(<form><input class="btn-red" type="submit" value="Override"></form>)");

    EXPECT_NE(page.find("data:image/svg+xml;base64,"), std::string::npos);
    EXPECT_NE(page.find("smithproxy"), std::string::npos);
    EXPECT_NE(page.find("TLS security warning"), std::string::npos);
    EXPECT_NE(page.find("class=\"reason\""), std::string::npos);
    EXPECT_NE(page.find("unsafe.example/&lt;script&gt;"), std::string::npos);
    EXPECT_EQ(page.find("<script>"), std::string::npos);
    EXPECT_EQ(page.find("src=\"http"), std::string::npos);
    EXPECT_EQ(page.find("href=\"http"), std::string::npos);
    EXPECT_EQ(page.find("<link"), std::string::npos);
}

TEST(ProxyMakerUtils, ParsesOnlyCompleteValidSourcePorts) {
    EXPECT_EQ(sx::proxymaker::parse_source_port("1"), 1);
    EXPECT_EQ(sx::proxymaker::parse_source_port("443"), 443);
    EXPECT_EQ(sx::proxymaker::parse_source_port("65535"), 65535);

    EXPECT_FALSE(sx::proxymaker::parse_source_port("").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("0").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("-1").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("65536").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("443x").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port(" 443").has_value());
}

namespace {

struct FakeProxy;

struct FakeCom {
    std::vector<int> monitored;
    std::vector<int> write_monitored;
    std::map<int, FakeProxy*> handlers;
    std::vector<int> valid_descriptors {12};
    bool descriptor_valid(int fd) const {
        return std::find(valid_descriptors.begin(), valid_descriptors.end(), fd)
               != valid_descriptors.end();
    }
    void set_monitor(int fd) { monitored.push_back(fd); }
    void set_write_monitor(int fd) { write_monitored.push_back(fd); }
    void set_poll_handler(int fd, FakeProxy* proxy) { handlers[fd] = proxy; }
};

struct FakeHost {
    int fd = -1;
    int connect_result = -1;
    FakeCom* transport = nullptr;
    int socket() const { return fd; }
    int connect() { return connect_result; }
    FakeCom* com() const { return transport; }
};

struct FakeProxy {
    static inline int destructed = 0;
    FakeHost* left = nullptr;
    FakeHost* right = nullptr;
    ~FakeProxy() { ++destructed; }
    FakeHost* first_left() const { return left; }
    FakeHost* first_right() const { return right; }
};

struct FakeOwner {
    explicit FakeOwner(FakeCom* value) : transport(value) {}
    FakeCom* transport = nullptr;
    std::unique_ptr<FakeProxy> child;
    FakeCom* com() { return transport; }
    void add_proxy(std::unique_ptr<FakeProxy> proxy) { child = std::move(proxy); }
};

} // namespace

TEST(ProxyMakerUtils, RejectsFailedUpstreamBeforeRegisteringHandlers) {
    FakeProxy::destructed = 0;
    FakeCom transport;
    FakeHost left{11, -1, &transport};
    FakeHost right{-1, -1, &transport};
    FakeOwner owner{&transport};
    auto proxy = std::make_unique<FakeProxy>();
    proxy->left = &left;
    proxy->right = &right;

    EXPECT_FALSE(sx::proxymaker::connect_owned_proxy(&owner, proxy));
    EXPECT_NE(proxy, nullptr);
    EXPECT_EQ(FakeProxy::destructed, 0);
    EXPECT_TRUE(transport.monitored.empty());
    EXPECT_TRUE(transport.write_monitored.empty());
    EXPECT_TRUE(transport.handlers.empty());
    EXPECT_EQ(owner.child, nullptr);
}

TEST(ProxyMakerUtils, RegistersBothSocketsBeforeTransferringOwnership) {
    FakeProxy::destructed = 0;
    FakeCom transport;
    FakeHost left{11, -1, &transport};
    FakeHost right{-1, 12, &transport};
    FakeOwner owner{&transport};
    auto proxy = std::make_unique<FakeProxy>();
    auto* identity = proxy.get();
    proxy->left = &left;
    proxy->right = &right;

    EXPECT_TRUE(sx::proxymaker::connect_owned_proxy(&owner, proxy));
    ASSERT_NE(owner.child, nullptr);
    EXPECT_EQ(proxy, nullptr);
    EXPECT_EQ(owner.child.get(), identity);
    EXPECT_EQ(transport.monitored, (std::vector<int>{11}));
    EXPECT_EQ(transport.write_monitored, (std::vector<int>{12}));
    EXPECT_EQ(transport.handlers.at(11), identity);
    EXPECT_EQ(transport.handlers.at(12), identity);
    EXPECT_EQ(FakeProxy::destructed, 0);
}

TEST(ProxyMakerUtils, AcceptsTransportValidatedVirtualDescriptor) {
    FakeCom transport;
    transport.valid_descriptors.push_back(-2);
    FakeHost left{11, -1, &transport};
    FakeHost right{-1, -2, &transport};
    FakeOwner owner{&transport};
    auto proxy = std::make_unique<FakeProxy>();
    proxy->left = &left;
    proxy->right = &right;

    EXPECT_TRUE(sx::proxymaker::connect_owned_proxy(&owner, proxy));
    ASSERT_NE(owner.child, nullptr);
    EXPECT_EQ(transport.monitored, (std::vector<int>{11}));
    EXPECT_EQ(transport.write_monitored, (std::vector<int>{-2}));
    EXPECT_EQ(transport.handlers.at(-2), owner.child.get());
}

TEST(ProxyMakerUtils, RejectsMissingEndpointTransportsBeforeProxySetup) {
    FakeCom transport;
    FakeHost valid{11, -1, &transport};
    FakeHost missing_transport{12, -1, nullptr};

    EXPECT_FALSE(sx::proxymaker::valid_host_pair<FakeHost>(nullptr, &valid));
    EXPECT_FALSE(sx::proxymaker::valid_host_pair<FakeHost>(&valid, nullptr));
    EXPECT_FALSE(sx::proxymaker::valid_host_pair(&valid, &missing_transport));
    EXPECT_TRUE(sx::proxymaker::valid_host_pair(&valid, &valid));

    FakeProxy proxy{&valid, &missing_transport};
    EXPECT_FALSE(sx::proxymaker::valid_proxy_endpoints(&proxy));
    proxy.right = &valid;
    EXPECT_TRUE(sx::proxymaker::valid_proxy_endpoints(&proxy));
}

namespace {

struct FakeDrainCom {
    std::vector<int> valid_descriptors;
    bool pending = false;
    bool descriptor_valid(int descriptor) const {
        return std::find(valid_descriptors.begin(), valid_descriptors.end(), descriptor)
               != valid_descriptors.end();
    }
    bool write_event_pending() const { return pending; }
};

struct FakeDrainBuffer {
    bool is_empty = true;
    bool empty() const { return is_empty; }
};

struct FakeDrainHost {
    int descriptor = 0;
    FakeDrainCom* transport = nullptr;
    FakeDrainBuffer pending;
    FakeDrainHost* other = nullptr;

    FakeDrainHost* peer() const { return other; }
    FakeDrainCom* com() const { return transport; }
    FakeDrainBuffer* writebuf() { return &pending; }
    int socket() const { return descriptor; }
};

} // namespace

TEST(MitmProxyLifecycle, HalfCloseRequiresPendingDataOnLivePeer) {
    FakeDrainCom transport{{12}};
    FakeDrainHost source{11, &transport, {}, nullptr};
    FakeDrainHost peer{12, &transport, {}, nullptr};
    source.other = &peer;

    EXPECT_FALSE(sx::mitmproxy::half_close_peer_can_drain<FakeDrainHost>(nullptr));
    EXPECT_FALSE(sx::mitmproxy::half_close_peer_can_drain(&source));

    peer.pending.is_empty = false;
    EXPECT_TRUE(sx::mitmproxy::half_close_peer_can_drain(&source));

    peer.descriptor = 13;
    EXPECT_FALSE(sx::mitmproxy::half_close_peer_can_drain(&source));
}

TEST(MitmProxyLifecycle, HalfCloseAcceptsTransportValidatedVirtualPeer) {
    FakeDrainCom transport{{-2}};
    FakeDrainHost source{11, &transport, {}, nullptr};
    FakeDrainHost peer{-2, &transport, {}, nullptr};
    peer.pending.is_empty = false;
    source.other = &peer;

    EXPECT_TRUE(sx::mitmproxy::half_close_peer_can_drain(&source));
}

TEST(MitmProxyLifecycle, UpstreamHalfCloseFinishesOnlyAfterPeerDrain) {
    FakeDrainCom transport{{12}};
    FakeDrainHost source{11, &transport, {}, nullptr};
    FakeDrainHost peer{12, &transport, {}, nullptr};
    source.other = &peer;

    EXPECT_TRUE(sx::mitmproxy::half_close_peer_drained(&source));

    peer.pending.is_empty = false;
    EXPECT_FALSE(sx::mitmproxy::half_close_peer_drained(&source));

    peer.pending.is_empty = true;
    transport.pending = true;
    EXPECT_FALSE(sx::mitmproxy::half_close_peer_drained(&source));

    transport.pending = false;
    peer.descriptor = 13;
    EXPECT_FALSE(sx::mitmproxy::half_close_peer_drained(&source));
}

TEST(MitmProxyLifecycle, HalfCloseGraceExpiresWithoutAnotherSocketError) {
    constexpr std::time_t started_at = 1000;

    EXPECT_FALSE(sx::mitmproxy::half_close_grace_expired(0, 5, 2000));
    EXPECT_FALSE(sx::mitmproxy::half_close_grace_expired(started_at, 5, 999));
    EXPECT_FALSE(sx::mitmproxy::half_close_grace_expired(started_at, 5, 1004));
    EXPECT_TRUE(sx::mitmproxy::half_close_grace_expired(started_at, 5, 1005));
    EXPECT_TRUE(sx::mitmproxy::half_close_grace_expired(started_at, 0, 1000));
}

TEST(MitmProxyTlsState, IncompleteJa4CaptureRetriesIndependently) {
    using action = sx::mitmproxy::hello_capture_action;

    EXPECT_EQ(sx::mitmproxy::hello_capture_next(false, 0, 5, 1, 10),
              action::disable);
    EXPECT_EQ(sx::mitmproxy::hello_capture_next(true, 6, 5, 0, 0),
              action::disable);
    EXPECT_EQ(sx::mitmproxy::hello_capture_next(true, 0, 5, 1, 10),
              action::retry);
    EXPECT_EQ(sx::mitmproxy::hello_capture_next(true, 5, 5, 9, 10),
              action::retry);
    EXPECT_EQ(sx::mitmproxy::hello_capture_next(true, 5, 5, 10, 10),
              action::disable);
    EXPECT_EQ(sx::mitmproxy::hello_capture_next(true, 6, 5, 1, 10),
              action::parse);
}

TEST(MitmProxyReplacement, EscapesHtmlAndRoundTripsSafeRelativeTargets) {
    EXPECT_EQ(sx::mitmproxy::html_escape("<&>\"'"),
              "&lt;&amp;&gt;&quot;&#39;");

    auto const original = "/path with spaces?q=\"x\"&next=/ok";
    auto const encoded = sx::mitmproxy::query_encode(original);
    EXPECT_EQ(encoded, "%2Fpath%20with%20spaces%3Fq%3D%22x%22%26next%3D%2Fok");
    EXPECT_EQ(sx::mitmproxy::decode_relative_target(encoded), original);
}

TEST(MitmProxyReplacement, RejectsExternalMalformedAndControlTargets) {
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("https%3A%2F%2Fevil.test").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2F%2Fevil.test").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2F%5Cevil.test").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("/\\evil.test").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2Fsafe%3Burl%3D%2F%2Fevil.test").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2Fsafe%2Curl%3D%2F%2Fevil.test").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2Fok%0D%0AX-Test%3Ayes").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%GG").has_value());
}

TEST(MitmProxyReplacement, MatchesOnlyBoundInternalActionRoutes) {
    using route = sx::mitmproxy::replacement_route;

    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/warning?q=1"),
              route::warning);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "GET /SM/IT/HP/RO/XY/warning?q=1 HTTP/1.1"),
              route::warning);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override/0123456789abcdef0123456789abcdef"),
              route::override_action);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "GET /SM/IT/HP/RO/XY/override/0123456789abcdef0123456789abcdef HTTP/1.1"),
              route::override_action);
    EXPECT_EQ(sx::mitmproxy::override_token_from_route(
                  "/SM/IT/HP/RO/XY/override/0123456789abcdef0123456789abcdef"),
              "0123456789abcdef0123456789abcdef");

    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/ordinary/path?/SM/IT/HP/RO/XY/override"),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override-pretend?token=x"),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override/not-hex"),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override/target=legacy"),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/warning-room"),
              route::none);

    auto const request =
        "/SM/IT/HP/RO/XY/override/0123456789abcdef0123456789abcdef"
        "?token=0123456789abcdef&orig_url=%2Fsafe";
    EXPECT_EQ(sx::mitmproxy::replacement_parameter(request, "token"),
              "0123456789abcdef");
    EXPECT_EQ(sx::mitmproxy::replacement_parameter(
                  "GET " + std::string(request) + " HTTP/1.1", "token"),
              "0123456789abcdef");
    EXPECT_EQ(sx::mitmproxy::replacement_parameter(request, "orig_url"),
              "%2Fsafe");
    EXPECT_EQ(sx::mitmproxy::query_parameter(
                  "q=1&orig_url=%2Fprotected%3Fx%3D1", "orig_url"),
              "%2Fprotected%3Fx%3D1");
    EXPECT_FALSE(sx::mitmproxy::replacement_parameter(request, "missing"));

    EXPECT_TRUE(sx::mitmproxy::override_token_matches(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef"));
    EXPECT_FALSE(sx::mitmproxy::override_token_matches(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdee"));
    EXPECT_FALSE(sx::mitmproxy::override_token_matches(
        "0123456789abcdef0123456789abcdef", std::nullopt));
    EXPECT_FALSE(sx::mitmproxy::override_token_matches("short", "short"));
}

TEST(MitmProxyReplacement, OverrideChallengeExpiresAndIsConsumedExactlyOnce) {
    sx::mitmproxy::override_challenge_store challenges;
    auto const token = "0123456789abcdef0123456789abcdef";

    challenges.issue("expired", token, 100, 2);
    EXPECT_FALSE(challenges.consume("expired", token, 102));

    challenges.issue("target", token, 100, 120);
    EXPECT_FALSE(challenges.consume(
        "other-target", token, 101));
    EXPECT_FALSE(challenges.consume(
        "target", "0123456789abcdef0123456789abcdee", 101));

    std::atomic<unsigned> accepted {0};
    std::vector<std::thread> contenders;
    for(unsigned i = 0; i < 16; ++i) {
        contenders.emplace_back([&] {
            if(challenges.consume("target", token, 101)) ++accepted;
        });
    }
    for(auto& contender: contenders) contender.join();
    EXPECT_EQ(accepted.load(), 1U);
    EXPECT_FALSE(challenges.consume("target", token, 101));

    challenges.issue("same-target", token, 200, 120);
    challenges.issue("same-target", "fedcba9876543210fedcba9876543210", 200, 120);
    EXPECT_TRUE(challenges.consume("same-target", token, 201));
    EXPECT_TRUE(challenges.consume(
        "same-target", "fedcba9876543210fedcba9876543210", 201));
}

TEST(MitmProxyReplacement, OverrideTimeoutCannotWrapToUnsignedLifetime) {
    EXPECT_FALSE(sx::mitmproxy::override_ttl_seconds(-1));
    EXPECT_FALSE(sx::mitmproxy::override_ttl_seconds(0));
    EXPECT_EQ(sx::mitmproxy::override_ttl_seconds(1), 1U);
    EXPECT_EQ(sx::mitmproxy::override_ttl_seconds(600), 600U);
}

TEST(MitmProxyReplacement, BrowserOverrideScopeIncludesNormalizedClientSni) {
    auto const l4 = "192.0.2.10:203.0.113.20:443";
    auto const first = sx::mitmproxy::override_scope_key(l4, "Bad-A.Example.");

    EXPECT_EQ(first, sx::mitmproxy::override_scope_key(l4, "bad-a.example"));
    EXPECT_NE(first, sx::mitmproxy::override_scope_key(l4, "bad-b.example"));
    EXPECT_NE(first, sx::mitmproxy::override_scope_key(l4, ""));
    EXPECT_NE(first, sx::mitmproxy::override_scope_key(
                         "192.0.2.10:203.0.113.21:443", "bad-a.example"));
    EXPECT_NE(sx::mitmproxy::override_scope_key("a:b", "c"),
              sx::mitmproxy::override_scope_key("a", "b:c"));
}

TEST(MitmProxyReplacement, ParsesOnlyCompleteFirstAlpnProtocol) {
    std::string const offered {"\x02h2\x08http/1.1", 12};
    EXPECT_EQ(sx::mitmproxy::first_alpn_protocol(offered), "h2");
    EXPECT_FALSE(sx::mitmproxy::first_alpn_protocol({}).has_value());
    EXPECT_FALSE(sx::mitmproxy::first_alpn_protocol(std::string_view("\0", 1)).has_value());
    EXPECT_FALSE(sx::mitmproxy::first_alpn_protocol(std::string_view("\x08h2", 3)).has_value());
}

TEST(MitmProxyTlsState, ClientCertificateActionsPreserveTheirDocumentedMeaning) {
    using action = sx::mitmproxy::client_certificate_action;

    EXPECT_EQ(sx::mitmproxy::client_certificate_next(false, 0), action::none);
    EXPECT_EQ(sx::mitmproxy::client_certificate_next(true, 0), action::block);
    EXPECT_EQ(sx::mitmproxy::client_certificate_next(true, 1), action::none);
    EXPECT_EQ(sx::mitmproxy::client_certificate_next(true, 2), action::whitelist_next);
    EXPECT_EQ(sx::mitmproxy::client_certificate_next(true, 3), action::none);
    EXPECT_EQ(sx::mitmproxy::client_certificate_next(true, 99), action::block);
}

TEST(MitmProxyTlsState, ClientCertificateRequestIsNotACertificateValidationFailure) {
    constexpr unsigned ok = 0x01;
    constexpr unsigned requested = 0x40;
    constexpr unsigned invalid = 0x08;

    EXPECT_FALSE(sx::mitmproxy::tls_verification_failed(ok, ok, requested));
    EXPECT_FALSE(sx::mitmproxy::tls_verification_failed(
        ok | requested, ok, requested));
    EXPECT_TRUE(sx::mitmproxy::tls_verification_failed(
        invalid | requested, ok, requested));
    EXPECT_FALSE(sx::mitmproxy::tls_verification_failed(requested, ok, requested));
}

TEST(MitmProxyReplacement, SharedRendererEnforcesScopedSingleUseOverrideAndExpiry) {
    std::string messages = "etc/msg/en/";
    ASSERT_TRUE(html()->load_files(messages));
    SSLCom verification;
    verification.opt.cert.failed_check_override = true;
    verification.opt.cert.failed_check_override_timeout = 10;
    verification.verify_reset(SSLCom::verify_status_t::VRF_UNKNOWN_ISSUER);
    sx::engine::http::app_HttpRequest request;
    request.version = sx::engine::http::app_HttpRequest::HTTP_VER::HTTP3;
    request.http_data.method = "GET";
    request.http_data.proto = "https://";
    request.http_data.host = "test.example";
    request.http_data.uri = "/SM/IT/HP/RO/XY/warning";
    request.http_data.params = "orig_url=%2Fhello%3Fx%3D1";
    const std::string scope = "replacement-unit:one";
    auto warning = MitmProxy::build_tls_replacement(&verification, &request, scope);
    EXPECT_EQ(warning.status, 403);
    EXPECT_FALSE(warning.override_applied);
    const std::string prefix = "/SM/IT/HP/RO/XY/override/";
    auto token_start = warning.body.find(prefix);
    ASSERT_NE(token_start, std::string::npos);
    auto token = warning.body.substr(token_start + prefix.size(), 32);
    ASSERT_EQ(token.size(), 32);
    request.http_data.uri = prefix + token;
    auto wrong_scope = MitmProxy::build_tls_replacement(&verification, &request, "replacement-unit:two");
    EXPECT_FALSE(wrong_scope.override_applied);
    EXPECT_EQ(wrong_scope.status, 403);
    auto accepted = MitmProxy::build_tls_replacement(&verification, &request, scope);
    EXPECT_TRUE(accepted.override_applied);
    EXPECT_EQ(accepted.status, 200);
    EXPECT_NE(accepted.body.find("/hello?x=1"), std::string::npos);
    EXPECT_TRUE(MitmProxy::tls_override_active(scope, verification.opt.cert));
    EXPECT_FALSE(MitmProxy::tls_override_active("replacement-unit:two", verification.opt.cert));
    auto replay = MitmProxy::build_tls_replacement(&verification, &request, scope);
    EXPECT_FALSE(replay.override_applied);
    {
        auto lock = std::scoped_lock(MitmProxy::whitelist_verify().getlock());
        auto entry = MitmProxy::whitelist_verify().get(scope);
        ASSERT_TRUE(entry);
        entry->expired_at() = std::time(nullptr) - 1;
    }
    EXPECT_FALSE(MitmProxy::tls_override_active(scope, verification.opt.cert));
}

TEST(MitmProxyReplacement, SharedRendererRejectsDisabledExpiredAndInvalidTtlOverrides) {
    SSLCom verification;
    sx::engine::http::app_HttpRequest request;
    request.http_data.uri = "/SM/IT/HP/RO/XY/override/0123456789abcdef0123456789abcdef";
    auto const scope = "replacement-unit:denied";
    auto issue = [&](std::time_t now) {
        MitmProxy::override_challenges().issue(scope,
            "0123456789abcdef0123456789abcdef", now, 120);
    };
    issue(std::time(nullptr));
    verification.opt.cert.failed_check_override = false;
    EXPECT_EQ(MitmProxy::build_tls_replacement(&verification, &request, scope).reason, "override disabled");
    verification.opt.cert.failed_check_override = true;
    verification.opt.cert.failed_check_override_timeout = -1;
    EXPECT_EQ(MitmProxy::build_tls_replacement(&verification, &request, scope).reason, "invalid override timeout");
    verification.opt.cert.failed_check_override_timeout = 10;
    issue(std::time(nullptr) - 121);
    EXPECT_EQ(MitmProxy::build_tls_replacement(&verification, &request, scope).reason, "invalid override challenge");
    EXPECT_FALSE(MitmProxy::tls_override_active(scope, verification.opt.cert));
}


TEST(MitmProxyReplacement, CertificateDetailsEscapePeerDataAndShowOriginalEvidence) {
    std::string messages = "etc/msg/en/";
    ASSERT_TRUE(html()->load_files(messages));
    struct CertificateEvidence : SSLCom {
        using SSLCom::sslcom_target_cert;
    } verification;
    verification.sslcom_target_cert = X509_new();
    auto* certificate = verification.target_cert();
    ASSERT_NE(certificate, nullptr);
    ASSERT_EQ(X509_set_version(certificate, 2), 1);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 42), 1);
    auto* subject = X509_get_subject_name(certificate);
    ASSERT_EQ(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        reinterpret_cast<unsigned char const*>("wrong.example<script>"), -1, -1, 0), 1);
    ASSERT_EQ(X509_set_issuer_name(certificate, subject), 1);
    ASSERT_EQ(ASN1_TIME_set_string(X509_getm_notBefore(certificate), "20200101000000Z"), 1);
    ASSERT_EQ(ASN1_TIME_set_string(X509_getm_notAfter(certificate), "20210101000000Z"), 1);
    auto san = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>(
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                           "DNS:wrong.example,DNS:other.example"), X509_EXTENSION_free);
    ASSERT_TRUE(san);
    ASSERT_EQ(X509_add_ext(certificate, san.get(), -1), 1);
    auto context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    ASSERT_TRUE(context);
    ASSERT_EQ(EVP_PKEY_keygen_init(context.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1), 1);
    EVP_PKEY* generated = nullptr;
    ASSERT_EQ(EVP_PKEY_keygen(context.get(), &generated), 1);
    auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(generated, EVP_PKEY_free);
    ASSERT_EQ(X509_set_pubkey(certificate, key.get()), 1);
    ASSERT_GT(X509_sign(certificate, key.get(), EVP_sha256()), 0);
    verification.verify_reset(SSLCom::verify_status_t::VRF_INVALID);
    verification.verify_bitset(SSLCom::verify_status_t::VRF_HOSTNAME_FAILED);
    sx::engine::http::app_HttpRequest request;
    request.http_data.host = "requested.example";
    request.http_data.proto = "https://";
    auto page = MitmProxy::replacement_ssl_page(&verification, &request, "");
    EXPECT_NE(page.find("<summary>More information</summary>"), std::string::npos);
    EXPECT_EQ(page.find("<script>"), std::string::npos);
    EXPECT_NE(page.find(R"(\&lt;script\&gt;)"), std::string::npos);
    EXPECT_NE(page.find("DNS:wrong.example, DNS:other.example"), std::string::npos);
    EXPECT_NE(page.find("Expired."), std::string::npos);
    EXPECT_NE(page.find("Client application asked for SNI server is not offering"), std::string::npos);
    EXPECT_NE(page.find("SHA-256 fingerprint</dt><dd>"), std::string::npos);
    EXPECT_EQ(page.find("SHA-256 fingerprint</dt><dd>Unavailable"), std::string::npos);
    EXPECT_EQ(page.find("BEGIN CERTIFICATE"), std::string::npos);
    if (auto* preview = std::getenv("SX_TLS_DETAILS_PREVIEW")) std::ofstream(preview) << page;

    ASSERT_EQ(ASN1_TIME_set_string(X509_getm_notBefore(certificate), "20990101000000Z"), 1);
    ASSERT_EQ(ASN1_TIME_set_string(X509_getm_notAfter(certificate), "21000101000000Z"), 1);
    page = MitmProxy::replacement_ssl_page(&verification, &request, "");
    EXPECT_NE(page.find("Not yet valid."), std::string::npos);
}

TEST(MitmProxyReplacement, CertificateDetailsHandleMissingEvidenceAndDoNotLeakBetweenPages) {
    std::string messages = "etc/msg/en/";
    ASSERT_TRUE(html()->load_files(messages));
    SSLCom verification;
    verification.verify_reset(SSLCom::verify_status_t::VRF_ALLFAILED);
    sx::engine::http::app_HttpRequest request;
    request.http_data.host = "missing.example";
    auto page = MitmProxy::replacement_ssl_page(&verification, &request, "");
    EXPECT_NE(page.find("Certificate unavailable"), std::string::npos);
    EXPECT_NE(page.find("It was not possible to obtain certificate status"), std::string::npos);
    page = MitmProxy::replacement_ssl_page(nullptr, &request, "");
    EXPECT_NE(page.find("Verification details unavailable"), std::string::npos);
    page = html()->render_tls_replacement("another.example", "", "");
    EXPECT_EQ(page.find("<details"), std::string::npos);
    EXPECT_EQ(page.find("missing.example"), std::string::npos);
}

TEST(MitmProxyReplacement, OverrideFormUsesFileTemplateWithEscapedValuesAndNoStaleState) {
    std::string messages = "etc/msg/en/";
    ASSERT_TRUE(html()->load_files(messages));

    auto form = html()->render_tls_override_form(
        "0123456789abcdef", sx::mitmproxy::html_escape("/path?x=\"<tag>&y=1"));

    EXPECT_NE(form.find("/SM/IT/HP/RO/XY/override/0123456789abcdef"), std::string::npos);
    EXPECT_NE(form.find("/path?x=&quot;&lt;tag&gt;&amp;y=1"), std::string::npos);
    EXPECT_EQ(form.find("<tag>"), std::string::npos);

    auto second = html()->render_tls_override_form("another-token", "/next");

    EXPECT_EQ(second.find("0123456789abcdef"), std::string::npos);
    EXPECT_EQ(second.find("/path?"), std::string::npos);
    EXPECT_NE(second.find("/next"), std::string::npos);
}

TEST(MitmProxyReplacement, FragmentsEscapeTextAndKeepRenderedMarkupAndStateSeparate) {
    std::string messages = "etc/msg/en/";
    ASSERT_TRUE(html()->load_files(messages));

    auto reason = html()->render_fields("tls_reason", {
        {"severity_class", " reason-critical"}, {"number", "1"},
        {"text", sx::mitmproxy::html_escape("unsafe <script> & issuer")}
    });
    EXPECT_NE(reason.find("class=\"reason reason-critical\""), std::string::npos);
    EXPECT_NE(reason.find("unsafe &lt;script&gt; &amp; issuer"), std::string::npos);

    auto details = html()->render_fields("tls_certificate_details", {
        {"reasons", reason}, {"fields", ""}
    });
    EXPECT_NE(details.find(reason), std::string::npos);
    EXPECT_EQ(details.find("&amp;lt;"), std::string::npos);

    auto next = html()->render_fields("tls_reason", {{"number", "2"}, {"text", "next"}});
    EXPECT_NE(next.find("class=\"reason\""), std::string::npos);
    EXPECT_EQ(next.find("unsafe"), std::string::npos);
    EXPECT_EQ(next.find("reason-critical"), std::string::npos);
}
