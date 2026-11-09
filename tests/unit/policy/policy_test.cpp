#include <proxy/policy_input.hpp>
#include <proxy/master_policy.hpp>
#include <tcpcom.hpp>
#include <udpcom.hpp>
#include <sslcom.hpp>

#include <policy/policy.hpp>
#include <proxy/proxymaker_policy.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/cfgapi/profile_runtime_options.hpp>
#include <log/logan.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <thread>

template<class Rule, class = void>
struct has_public_rule_match : std::false_type {};
template<class Rule>
struct has_public_rule_match<Rule, std::void_t<decltype(std::declval<Rule&>().match(
    std::declval<std::vector<baseHostCX*>&>(), std::declval<std::vector<baseHostCX*>&>()))>>
    : std::true_type {};
static_assert(!has_public_rule_match<PolicyRule>::value,
              "Complete rule matching must remain private to proxymaker");

template<class Rule, class = void>
struct has_public_proxy_match : std::false_type {};
template<class Rule>
struct has_public_proxy_match<Rule, std::void_t<decltype(std::declval<Rule&>().match(
    std::declval<baseProxy*>()))>> : std::true_type {};
static_assert(!has_public_proxy_match<PolicyRule>::value,
              "Live proxy rule matching must remain private to proxymaker");

// Exercise the same gated selector used by production; no test-only friendship.
template<class... Context>
bool selects_rule(PolicyRule& rule, Context&&... context) {
    auto borrowed = std::shared_ptr<PolicyRule>(&rule, [](PolicyRule*) {});
    return sx::proxymaker::PolicyMatcher::select({borrowed}, std::forward<Context>(context)...) == 0;
}

using namespace cidr;

TEST(PolicyRuntimeOptions, ProfileNamesHaveOwnedLifetimeAndFallback) {
    auto profile = std::make_shared<ProfileTls>();
    profile->element_name() = "strict-tls";

    auto name = cfgapi_detail::profile_name_or(profile);
    profile->element_name() = "changed-after-capture";
    EXPECT_EQ(name, "strict-tls");

    std::shared_ptr<ProfileTls> missing;
    EXPECT_EQ(cfgapi_detail::profile_name_or(missing), "none");
    EXPECT_EQ(cfgapi_detail::profile_name_or(missing, "disabled"), "disabled");
}

TEST(PolicyRuntimeOptions, FailOpenRequiresAnExplicitValueInEveryGeneration) {
    EXPECT_TRUE(cfgapi_detail::fail_open_setting(true, true));
    EXPECT_FALSE(cfgapi_detail::fail_open_setting(true, false));
    EXPECT_FALSE(cfgapi_detail::fail_open_setting(false, true));
    EXPECT_FALSE(cfgapi_detail::fail_open_setting(false, false));
}

TEST(PolicyRuntimeOptions, ContentRuleRegexMustCompileBeforePublication) {
    EXPECT_TRUE(cfgapi_detail::valid_content_rule_pattern("secret-[0-9]+"));
    EXPECT_TRUE(cfgapi_detail::valid_content_rule_pattern("^"));
    EXPECT_FALSE(cfgapi_detail::valid_content_rule_pattern(""));
    EXPECT_FALSE(cfgapi_detail::valid_content_rule_pattern("[unterminated"));
    EXPECT_FALSE(cfgapi_detail::valid_content_rule_pattern("(unclosed"));
}

TEST(PolicyRuntimeOptions, ContentRulePersistenceRetainsReplacementSemantics) {
    ProfileContentRule rule;
    rule.match = "secret";
    rule.replace = "[redacted]";
    rule.fill_length = true;
    rule.replace_each_nth = 7;
    libconfig::Config saved;
    auto& serialized = saved.getRoot().add("rule", libconfig::Setting::TypeGroup);
    cfgapi_detail::save_content_rule(serialized, rule);
    EXPECT_TRUE(static_cast<bool>(serialized["fill_length"]));
    EXPECT_EQ(static_cast<int>(serialized["replace_each_nth"]), 7);
}

TEST(PolicyRuntimeOptions, EmptyDependencyReloadStillRebuildsPolicies) {
    int dependency_calls = 0;
    int policy_calls = 0;
    EXPECT_FALSE(cfgapi_detail::reload_policy_dependency(
        [&] { ++dependency_calls; return 0; },
        [&] { ++policy_calls; return 1; }));
    EXPECT_EQ(dependency_calls, 1);
    EXPECT_EQ(policy_calls, 1);

    EXPECT_TRUE(cfgapi_detail::reload_policy_dependency(
        [&] { ++dependency_calls; return 1; },
        [&] { ++policy_calls; return 1; }));
    EXPECT_EQ(dependency_calls, 2);
    EXPECT_EQ(policy_calls, 2);
}

TEST(PolicyRuntimeOptions, NamedDependencyAddsRequirePolicyRebuild) {
    for(auto const section: {
            "proto_objects", "port_objects", "address_objects",
            "detection_profiles", "content_profiles", "tls_profiles",
            "ssh_profiles", "alg_dns_profiles", "script_profiles",
            "auth_profiles", "routing"}) {
        EXPECT_TRUE(cfgapi_detail::policy_dependency_section(section)) << section;
    }
    EXPECT_FALSE(cfgapi_detail::policy_dependency_section("policy"));
    EXPECT_FALSE(cfgapi_detail::policy_dependency_section("tls_ca"));
    EXPECT_FALSE(cfgapi_detail::policy_dependency_section("settings"));
}

TEST(PolicyRuntimeOptions, DiagnosticsExposeConfiguredScriptProfile) {
    PolicyRule rule;
    rule.profile_script = std::make_shared<ProfileScript>();
    rule.profile_script->element_name() = "audit-script";

    EXPECT_NE(rule.to_string(iDIA).find("script=audit-script"),
              std::string::npos);
}

TEST(PolicyRuntimeOptions, DegradedPolicySerializesFailClosed) {
    PolicyRule rule;
    rule.action_name = "accept";
    rule.cfg_err_is_degraded = true;
    EXPECT_EQ(cfgapi_detail::policy_action_for_save(rule), "deny");

    rule.cfg_err_is_degraded = false;
    EXPECT_EQ(cfgapi_detail::policy_action_for_save(rule), "accept");
}

TEST(PolicyTest, ExplicitAuthorizationIsBoundToTheRuleAcrossReload) {
    auto authorized = std::make_shared<PolicyRule>();
    auto replacement_at_same_index = std::make_shared<PolicyRule>();

    EXPECT_TRUE(sx::policy::authorized_snapshot_is_current(
        authorized, authorized));
    EXPECT_FALSE(sx::policy::authorized_snapshot_is_current(
        authorized, replacement_at_same_index));
    EXPECT_FALSE(sx::policy::authorized_snapshot_is_current(
        authorized, {}));
    EXPECT_FALSE(sx::policy::authorized_snapshot_is_current(
        {}, replacement_at_same_index));

    EXPECT_TRUE(sx::policy::implicit_pass_is_current(false, false));
    EXPECT_TRUE(sx::policy::implicit_pass_is_current(false, true));
    EXPECT_TRUE(sx::policy::implicit_pass_is_current(true, true));
    EXPECT_FALSE(sx::policy::implicit_pass_is_current(true, false));
}

TEST(ProfileTlsTest, ClientCertificateActionNamesFailClosed) {
    EXPECT_EQ(ProfileTls::normalized_client_cert_action(0), 0);
    EXPECT_EQ(ProfileTls::normalized_client_cert_action(1), 1);
    EXPECT_EQ(ProfileTls::normalized_client_cert_action(2), 2);
    EXPECT_EQ(ProfileTls::normalized_client_cert_action(3), 3);
    EXPECT_EQ(ProfileTls::normalized_client_cert_action(-1), 0);
    EXPECT_EQ(ProfileTls::normalized_client_cert_action(4), 0);

    EXPECT_EQ(ProfileTls::client_cert_action_name(0), "block_or_replacement");
    EXPECT_EQ(ProfileTls::client_cert_action_name(1), "empty_client_cert");
    EXPECT_EQ(ProfileTls::client_cert_action_name(2), "tls_bypass");
    EXPECT_EQ(ProfileTls::client_cert_action_name(3), "use_configured");
    EXPECT_EQ(ProfileTls::client_cert_action_name(999), "block_or_replacement");
    EXPECT_EQ(ProfileTls::client_cert_action_value("block_or_replacement"), 0);
    EXPECT_EQ(ProfileTls::client_cert_action_value("empty_client_cert"), 1);
    EXPECT_EQ(ProfileTls::client_cert_action_value("tls_bypass"), 2);
    EXPECT_EQ(ProfileTls::client_cert_action_value("use_configured"), 3);
    EXPECT_EQ(ProfileTls::client_cert_action_value("invalid"), 0);
}

TEST(ProfileTlsTest, RevocationModesRejectValuesOutsideTheirDomain) {
    EXPECT_TRUE(ProfileTls::valid_revocation_mode(0));
    EXPECT_TRUE(ProfileTls::valid_revocation_mode(1));
    EXPECT_TRUE(ProfileTls::valid_revocation_mode(2));
    EXPECT_FALSE(ProfileTls::valid_revocation_mode(-1));
    EXPECT_FALSE(ProfileTls::valid_revocation_mode(3));
    EXPECT_FALSE(ProfileTls::valid_revocation_mode(999));
}

TEST(ProfileTlsTest, ReplacementPortIdentityRequiresACompleteTransportPort) {
    EXPECT_EQ(cfgapi_detail::parse_transport_port("0"), 0);
    EXPECT_EQ(cfgapi_detail::parse_transport_port("443"), 443);
    EXPECT_EQ(cfgapi_detail::parse_transport_port("65535"), 65535);

    for(auto const malformed : {
            "", " 443", "443 ", "443garbage", "+443", "-1", "65536"}) {
        EXPECT_FALSE(cfgapi_detail::parse_transport_port(malformed).has_value())
            << malformed;
    }

    EXPECT_TRUE(cfgapi_detail::replacement_redirect_port_matches("443"));
    EXPECT_FALSE(cfgapi_detail::replacement_redirect_port_matches("443garbage"));
    std::set<int> configured{8443};
    EXPECT_TRUE(cfgapi_detail::replacement_redirect_port_matches(
        "8443", &configured));
    EXPECT_FALSE(cfgapi_detail::replacement_redirect_port_matches(
        "443", &configured));
}

TEST(ProfileTlsTest, ReplacementRedirectFailsClosedWithoutAConnection) {
    auto profile = std::make_shared<ProfileTls>();
    SSLCom connection;

    EXPECT_TRUE(cfgapi_detail::replacement_redirect_state_complete(
        profile, &connection));
    EXPECT_FALSE(cfgapi_detail::replacement_redirect_state_complete(
        profile, static_cast<SSLCom*>(nullptr)));
    EXPECT_FALSE(cfgapi_detail::replacement_redirect_state_complete(
        std::shared_ptr<ProfileTls>{}, &connection));
}

TEST(ProfileTlsTest, TenantPortOffsetCannotChangeTheTransportDomain) {
    EXPECT_EQ(cfgapi_detail::offset_transport_port("0", 0), 0);
    EXPECT_EQ(cfgapi_detail::offset_transport_port("443", 7), 450);
    EXPECT_EQ(cfgapi_detail::offset_transport_port("65534", 1), 65535);

    EXPECT_FALSE(cfgapi_detail::offset_transport_port("65535", 1));
    EXPECT_FALSE(cfgapi_detail::offset_transport_port("65534", 2));
    EXPECT_FALSE(cfgapi_detail::offset_transport_port("443suffix", 1));
    EXPECT_FALSE(cfgapi_detail::offset_transport_port("-1", 1));
    EXPECT_FALSE(cfgapi_detail::offset_transport_port("1", 65535));
}

TEST(ProfileTlsTest, ApplyingAnEmptyProfileRetiresThePreviousSniBypassFilter) {
    auto active = std::make_shared<std::vector<std::string>>(
        std::initializer_list<std::string>{"*.legacy.example"});
    auto replacement = std::make_shared<std::vector<std::string>>(
        std::initializer_list<std::string>{"current.example"});

    cfgapi_detail::replace_sni_bypass_filter(active, replacement);
    ASSERT_EQ(active, replacement);
    ASSERT_EQ(active->at(0), "current.example");

    cfgapi_detail::replace_sni_bypass_filter(active, {});
    EXPECT_EQ(active, nullptr);
}

TEST(ProfileTlsTest, DnsBackedSniBypassRequiresPairedRuntimeObjects) {
    auto profile = std::make_shared<ProfileTls>();
    EXPECT_TRUE(cfgapi_detail::dns_sni_bypass_state_complete(profile));

    profile->sni_filter_bypass = std::make_shared<std::vector<std::string>>(
        std::initializer_list<std::string>{"one.example", "two.example"});
    EXPECT_FALSE(cfgapi_detail::dns_sni_bypass_state_complete(profile));

    profile->sni_filter_bypass_addrobj =
        std::make_shared<std::vector<FqdnAddress>>();
    profile->sni_filter_bypass_addrobj->emplace_back("one.example");
    EXPECT_FALSE(cfgapi_detail::dns_sni_bypass_state_complete(profile));

    profile->sni_filter_bypass_addrobj->emplace_back("two.example");
    EXPECT_TRUE(cfgapi_detail::dns_sni_bypass_state_complete(profile));

    profile->sni_filter_use_dns_cache = false;
    profile->sni_filter_bypass_addrobj.reset();
    EXPECT_TRUE(cfgapi_detail::dns_sni_bypass_state_complete(profile));
    EXPECT_FALSE(cfgapi_detail::dns_sni_bypass_state_complete(
        std::shared_ptr<ProfileTls>{}));
}

TEST(ProfileTlsTest, ReapplyingTlsPolicyRetiresPeerReplacement) {
    SSLCom peer;
    peer.opt.cert.failed_check_replacement = false;

    cfgapi_detail::replace_peer_replacement_state(peer.opt.cert, true, true);
    EXPECT_TRUE(peer.opt.cert.failed_check_replacement);

    cfgapi_detail::replace_peer_replacement_state(peer.opt.cert, false, true);
    EXPECT_FALSE(peer.opt.cert.failed_check_replacement);

    cfgapi_detail::replace_peer_replacement_state(peer.opt.cert, true, false);
    EXPECT_FALSE(peer.opt.cert.failed_check_replacement);
}

TEST(ProfileTlsTest, CommonPfsSettingIsTheDirectionalDefault) {
    auto load = [](ProfileTls& profile,
                   std::optional<bool> common,
                   std::optional<bool> left,
                   std::optional<bool> right) {
        cfgapi_detail::load_pfs_options(profile,
            [&](std::string_view option, bool& value) {
                auto const* configured = option == "use_pfs" ? &common
                    : option == "left_use_pfs" ? &left : &right;
                if(*configured) value = **configured;
            });
    };

    ProfileTls common_off;
    load(common_off, false, std::nullopt, std::nullopt);
    EXPECT_FALSE(common_off.use_pfs);
    EXPECT_FALSE(common_off.left_use_pfs);
    EXPECT_FALSE(common_off.right_use_pfs);

    ProfileTls left_override;
    load(left_override, false, true, std::nullopt);
    EXPECT_TRUE(left_override.left_use_pfs);
    EXPECT_FALSE(left_override.right_use_pfs);

    ProfileTls right_override;
    load(right_override, true, std::nullopt, false);
    EXPECT_TRUE(right_override.left_use_pfs);
    EXPECT_FALSE(right_override.right_use_pfs);
}

TEST(ProfileContentTest, Ja4HttpSettingControlsTheHttpFingerprintParser) {
    struct AccountingOptions { bool ja4_http = true; } accounting;
    struct HttpOptions { bool ja4h = true; } http;

    cfgapi_detail::apply_ja4_http_option(false, accounting, http);
    EXPECT_FALSE(accounting.ja4_http);
    EXPECT_FALSE(http.ja4h);

    cfgapi_detail::apply_ja4_http_option(true, accounting, http);
    EXPECT_TRUE(accounting.ja4_http);
    EXPECT_TRUE(http.ja4h);

    cfgapi_detail::apply_ja4_http_option(false, accounting, http);
    EXPECT_FALSE(accounting.ja4_http);
    EXPECT_FALSE(http.ja4h);
}

TEST(PolicyTest, match_addrgrp_cx) {
    PolicyRule p;
    auto h = baseHostCX(new TCPCom(), "192.168.1.1", "80");

    PolicyRule::group_of_addresses g;

    // matching range
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.1.0/24")));
    ASSERT_TRUE(p.match_addrgrp_cx(g, &h));

    // empty should return true
    g.clear();
    ASSERT_TRUE(p.match_addrgrp_cx(g, &h));

    // different subnet must return false
    g.clear();
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.11.0/24")));
    ASSERT_FALSE(p.match_addrgrp_cx(g, &h));

    // two ranges one should match
    g.clear();
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.11.0/24")));
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.1.0/24")));
    ASSERT_TRUE(p.match_addrgrp_cx(g, &h));


    // two ranges NONE should match
    g.clear();
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.11.0/24")));
    g.push_back(std::make_shared<CfgAddress>(std::make_shared<CidrAddress>("192.168.21.0/24")));
    ASSERT_FALSE(p.match_addrgrp_cx(g, &h));
}

TEST(PolicyTest, PortMatchingRejectsAmbiguousEndpointIdentity) {
    PolicyRule policy;
    auto exact = std::make_shared<CfgRange>(std::pair<int, int>{443, 443});
    PolicyRule::group_of_ports ports{exact};

    auto valid = baseHostCX(new TCPCom(), "192.0.2.10", "443");
    EXPECT_TRUE(policy.match_rangegrp_cx(ports, &valid));

    for(const char* malformed : {
            "443garbage", "443 ", " 443", "-1", "65536", ""}) {
        auto endpoint = baseHostCX(new TCPCom(), "192.0.2.10", malformed);
        EXPECT_FALSE(policy.match_rangegrp_cx(ports, &endpoint)) << malformed;
        EXPECT_FALSE(policy.match_rangegrp_cx({}, &endpoint)) << malformed;
    }

    auto zero = baseHostCX(new TCPCom(), "192.0.2.10", "0");
    EXPECT_TRUE(policy.match_rangegrp_cx({}, &zero));
}

TEST(PolicyTest, MatchCounterIsExactUnderConcurrentTraffic) {
    PolicyRule policy;
    baseHostCX left(new TCPCom(), "192.0.2.10", "40000");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    std::vector<baseHostCX*> lefts{&left};
    std::vector<baseHostCX*> rights{&right};

    constexpr unsigned int workers = 8;
    constexpr unsigned int matches_per_worker = 1000;
    std::atomic_bool all_matched{true};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for(unsigned int i = 0; i < workers; ++i) {
        threads.emplace_back([&] {
            for(unsigned int match = 0; match < matches_per_worker; ++match)
                if(!selects_rule(policy, lefts, rights)) all_matched = false;
        });
    }
    for(auto& thread : threads) thread.join();

    EXPECT_TRUE(all_matched.load());
    EXPECT_EQ(__atomic_load_n(&policy.cnt_matches, __ATOMIC_RELAXED),
              workers * matches_per_worker);
}


TEST(PolicyTest, match_rangevec_cx) {
    PolicyRule p;
    auto h = baseHostCX(new TCPCom(), "192.168.1.1", "80");

    PolicyRule::group_of_ports g;

    // matching range
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(80,80)));
    ASSERT_TRUE(p.match_rangegrp_cx(g, &h));

    // empty should return true
    g.clear();
    ASSERT_TRUE(p.match_rangegrp_cx(g, &h));

    // different subnet must return false
    g.clear();
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(443,443)));
    ASSERT_FALSE(p.match_rangegrp_cx(g, &h));

    // two ranges one should match
    g.clear();
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(443,443)));
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(0,65535)));
    ASSERT_TRUE(p.match_rangegrp_cx(g, &h));


    // two ranges NONE should match
    g.clear();
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(443,443)));
    g.push_back(std::make_shared<CfgRange>(std::pair<int, int>(143,143)));
    ASSERT_FALSE(p.match_rangegrp_cx(g, &h));
}

TEST(PolicyTest, ExplicitFirstRuleIsNeverRematchedDuringApplication) {
    unsigned matcher_calls = 0;
    auto matcher = [&] {
        ++matcher_calls;
        return 7;
    };

    EXPECT_EQ(sx::policy::preserve_explicit_match(0, matcher), 0);
    EXPECT_EQ(matcher_calls, 0U);
    EXPECT_EQ(sx::policy::preserve_explicit_match(3, matcher), 3);
    EXPECT_EQ(matcher_calls, 0U);
    EXPECT_EQ(sx::policy::preserve_explicit_match(-1, matcher), 7);
    EXPECT_EQ(matcher_calls, 1U);
}

TEST(PolicyTest, DirectMatchRequiresCompleteNonNullEndpointSets) {
    PolicyRule rule;
    baseHostCX left(new TCPCom(), "192.0.2.10", "12345");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    std::vector<baseHostCX*> empty;
    std::vector<baseHostCX*> lefts{&left};
    std::vector<baseHostCX*> rights{&right};

    EXPECT_FALSE(selects_rule(rule, empty, rights));
    EXPECT_FALSE(selects_rule(rule, lefts, empty));
    lefts.push_back(nullptr);
    EXPECT_FALSE(selects_rule(rule, lefts, rights));

    lefts = {&left};
    // The public setter now rejects a null COM. Deliberately corrupt only
    // this fixture to retain the policy's defensive missing-transport check.
    class MissingTransportCX : public baseHostCX {
    public:
        MissingTransportCX() : baseHostCX(new TCPCom(), "192.0.2.11", "12345") {
            saved_ = std::move(com_);
        }
        ~MissingTransportCX() override { com_ = std::move(saved_); }
    private:
        std::unique_ptr<baseCom> saved_;
    } missing_transport;
    lefts.push_back(&missing_transport);
    // A wildcard protocol used to skip the only com() validation and let
    // this incomplete endpoint participate in an allow-rule match.
    EXPECT_FALSE(selects_rule(rule, lefts, rights));
}

TEST(PolicyTest, EveryEndpointMustMatchAddressAndPortOnTheSameFlowSet) {
    PolicyRule rule;
    rule.src.push_back(std::make_shared<CfgAddress>(
        std::make_shared<CidrAddress>("192.0.2.10/32")));
    rule.src_ports.push_back(std::make_shared<CfgRange>(
        std::pair<int, int>(2000, 2000)));

    baseHostCX address_only(new TCPCom(), "192.0.2.10", "1000");
    baseHostCX port_only(new TCPCom(), "192.0.2.11", "2000");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    std::vector<baseHostCX*> lefts{&address_only, &port_only};
    std::vector<baseHostCX*> rights{&right};

    // The address used to match the first endpoint and the port the second,
    // incorrectly authorizing the whole set although no endpoint matched the
    // complete source predicate.
    EXPECT_FALSE(selects_rule(rule, lefts, rights));

    address_only.port("2000");
    lefts.resize(1);
    EXPECT_TRUE(selects_rule(rule, lefts, rights));
}

TEST(PolicyTest, ProtocolAndMalformedEndpointFailuresAreFailClosed) {
    PolicyRule rule;
    rule.proto = std::make_shared<CfgUint8>(6);
    baseHostCX tcp(new TCPCom(), "192.0.2.10", "1000");
    baseHostCX udp(new UDPCom(), "198.51.100.20", "53");
    std::vector<baseHostCX*> lefts{&tcp};
    std::vector<baseHostCX*> rights{&udp};

    EXPECT_FALSE(selects_rule(rule, lefts, rights));

    rule.proto = std::make_shared<CfgUint8>(0);
    rule.src.push_back(std::make_shared<CfgAddress>(
        std::make_shared<CidrAddress>("192.0.2.0/24")));
    tcp.host("not-an-ip-address");
    EXPECT_NO_THROW(EXPECT_FALSE(selects_rule(rule, lefts, rights)));
    tcp.host("192.0.2.10");
    tcp.port("invalid");
    rule.src_ports.push_back(std::make_shared<CfgRange>(
        std::pair<int, int>(1, 65535)));
    EXPECT_FALSE(selects_rule(rule, lefts, rights));
}

TEST(PolicyTest, UserDisabledRulesSkipButConfigurationErrorsStopSelection) {
    PolicyRule rule;
    baseHostCX left(new TCPCom(), "192.0.2.10", "1000");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    std::vector<baseHostCX*> lefts{&left};
    std::vector<baseHostCX*> rights{&right};

    rule.is_disabled = true;
    EXPECT_FALSE(selects_rule(rule, lefts, rights));
    rule.is_disabled = false;
    rule.cfg_err_is_disabled = true;
    EXPECT_TRUE(selects_rule(rule, lefts, rights));
    rule.cfg_err_is_disabled = false;
    rule.cfg_err_is_degraded = true;
    EXPECT_TRUE(selects_rule(rule, lefts, rights));
}

#include <proxy/network_policy.hpp>

TEST(PolicyInterfaces, MatchesBothRolesAndRejectsUnknownMetadata) {
    sx::net::InterfaceSnapshot network;
    network.valid = network.roles_valid = true;
    network.interfaces = {{2, "lan", 0, "Office"}, {3, "wan", 0, "Outside"}};
    baseHostCX left(new TCPCom(), "192.0.2.10", "12345");
    baseHostCX right(new TCPCom(), "198.51.100.20", "443");
    left.com()->ingress_ifindex(2);
    right.com()->egress_ifindex(3);
    auto rule = std::make_shared<PolicyRule>();
    rule->ingress_role = "Office"; rule->egress_role = "Outside";
    EXPECT_TRUE(rule->match_roles({&left}, {&right}, network));
    std::vector<baseHostCX*> lefts{&left}, rights{&right};
    EXPECT_TRUE(selects_rule(*rule, lefts, rights, &network));
    rule->ingress_role = "Guest";
    EXPECT_FALSE(rule->match_roles({&left}, {&right}, network));
    EXPECT_FALSE(selects_rule(*rule, lefts, rights, &network));
    rule->ingress_role = "Office";
    right.com()->egress_ifindex(0);
    EXPECT_FALSE(rule->match_roles({&left}, {&right}, network));
    rule->egress_role.clear();
    EXPECT_TRUE(sx::proxy::prepare_network_policy({rule}, {&left}, {&right}, network));
    left.com()->ingress_ifindex(0);
    EXPECT_FALSE(sx::proxy::prepare_network_policy({rule}, {&left}, {&right}, network));
    rule->is_disabled = true;
    EXPECT_TRUE(sx::proxy::prepare_network_policy({rule}, {&left}, {&right}, network));
}

TEST(MasterPolicyState, UnchangedGenerationsDoNotRequireRevalidation) {
    sx::proxy::policy_state_t state;
    EXPECT_TRUE(state.validate(state.observed));
    EXPECT_FALSE(state.revalidation_required);
}

TEST(MasterPolicyState, EachGenerationChangeRemainsPendingUntilRevalidated) {
    using State = sx::proxy::policy_state_t;
    for(auto member : {&State::generations_t::policy, &State::generations_t::route,
                       &State::generations_t::role}) {
        State state;
        auto changed = state.observed;
        ++(changed.*member);
        EXPECT_FALSE(state.validate(changed));
        EXPECT_TRUE(state.revalidation_required);
        EXPECT_EQ(state.observed, changed);
        EXPECT_FALSE(state.validate(changed)); // checking again is not completion
        ++(changed.*member);
        EXPECT_FALSE(state.validate(changed)); // another change is retained too
        EXPECT_EQ(state.observed, changed);
    }
}

TEST(MasterPolicyState, MastersObserveChangesIndependently) {
    sx::proxy::policy_state_t first, second;
    second.observed = first.observed;
    auto changed = first.observed;
    ++changed.policy;
    EXPECT_FALSE(first.validate(changed));
    EXPECT_TRUE(second.validate(second.observed));
    EXPECT_FALSE(second.validate(changed));
    EXPECT_TRUE(first.revalidation_required);
    EXPECT_TRUE(second.revalidation_required);
}

TEST(PolicyRevalidation, OriginalInputsSurviveRoutingAndContextDestruction) {
    auto left = std::make_unique<baseHostCX>(new TCPCom, "192.0.2.10", "12345");
    auto right = std::make_unique<baseHostCX>(new TCPCom, "203.0.113.10", "443");
    left->com()->ingress_ifindex(7);
    left->com()->l4_proto(SOCK_DGRAM);
    auto saved = sx::proxy::policy_input_t::capture({left.get()}, {right.get()});
    right->host("127.0.0.1");
    left.reset(); right.reset();
    auto view = saved.view();
    EXPECT_EQ(view.right.front()->host(), "203.0.113.10");
    EXPECT_EQ(view.right.front()->port(), "443");
    EXPECT_EQ(view.left.front()->com()->ingress_ifindex(), 7u);
    EXPECT_EQ(view.left.front()->com()->policy_l4_proto(), SOCK_DGRAM);
}

TEST(PolicyRevalidation, RecheckingDoesNotCountAnotherConnection) {
    auto rule = std::make_shared<PolicyRule>();
    baseHostCX left(new TCPCom, "192.0.2.10", "12345");
    baseHostCX right(new TCPCom, "203.0.113.10", "443");
    auto input = sx::proxy::policy_input_t::capture({&left}, {&right});
    auto view = input.view();
    EXPECT_EQ(sx::proxymaker::PolicyMatcher::select({rule}, view.left, view.right), 0);
    const auto admitted = rule->cnt_matches;
    EXPECT_EQ(sx::proxymaker::PolicyMatcher::select({rule}, view.left, view.right,
        static_cast<const sx::net::InterfaceSnapshot*>(nullptr), false), 0);
    EXPECT_EQ(rule->cnt_matches, admitted);
}
