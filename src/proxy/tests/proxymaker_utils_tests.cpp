#include <gtest/gtest.h>

#include <proxy/mitmproxy_utils.hpp>
#include <proxy/proxymaker_utils.hpp>
#include <staticcontent.hpp>

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
    std::map<int, FakeProxy*> handlers;
    std::vector<int> valid_descriptors {12};
    bool descriptor_valid(int fd) const {
        return std::find(valid_descriptors.begin(), valid_descriptors.end(), fd)
               != valid_descriptors.end();
    }
    void set_monitor(int fd) { monitored.push_back(fd); }
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

    EXPECT_FALSE(sx::proxymaker::connect_owned_proxy(&owner, std::move(proxy)));
    EXPECT_NE(proxy, nullptr);
    EXPECT_TRUE(transport.monitored.empty());
    EXPECT_TRUE(transport.handlers.empty());
    EXPECT_EQ(owner.child, nullptr);
    proxy.reset();
    EXPECT_EQ(FakeProxy::destructed, 1);
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

    EXPECT_TRUE(sx::proxymaker::connect_owned_proxy(&owner, std::move(proxy)));
    ASSERT_NE(owner.child, nullptr);
    EXPECT_EQ(owner.child.get(), identity);
    EXPECT_EQ(transport.monitored, (std::vector<int>{12}));
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

    EXPECT_TRUE(sx::proxymaker::connect_owned_proxy(&owner, std::move(proxy)));
    ASSERT_NE(owner.child, nullptr);
    EXPECT_EQ(transport.monitored, (std::vector<int>{-2}));
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
    bool descriptor_valid(int descriptor) const {
        return std::find(valid_descriptors.begin(), valid_descriptors.end(), descriptor)
               != valid_descriptors.end();
    }
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
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2Fok%0D%0AX-Test%3Ayes").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%2").has_value());
    EXPECT_FALSE(sx::mitmproxy::decode_relative_target("%GG").has_value());
}

TEST(MitmProxyReplacement, MatchesOnlyBoundInternalActionRoutes) {
    using route = sx::mitmproxy::replacement_route;
    auto const key = "192.0.2.10:expired.example:443";

    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/warning?q=1", key),
              route::warning);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override/target=192.0.2.10:expired.example:443&orig_url=%2F", key),
              route::override_action);

    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/ordinary/path?/SM/IT/HP/RO/XY/override", key),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override-pretend/target=192.0.2.10:expired.example:443", key),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override/target=192.0.2.10:other.example:443", key),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/override/target=192.0.2.10:expired.example:443", {}),
              route::none);
    EXPECT_EQ(sx::mitmproxy::classify_replacement_route(
                  "/SM/IT/HP/RO/XY/warning-room", key),
              route::none);

    auto const request =
        "/SM/IT/HP/RO/XY/override/target=192.0.2.10:expired.example:443"
        "&token=0123456789abcdef&orig_url=%2Fsafe";
    EXPECT_EQ(sx::mitmproxy::replacement_parameter(request, "token"),
              "0123456789abcdef");
    EXPECT_EQ(sx::mitmproxy::replacement_parameter(request, "orig_url"),
              "%2Fsafe");
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
    EXPECT_EQ(sx::mitmproxy::client_certificate_next(true, 99), action::none);
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
