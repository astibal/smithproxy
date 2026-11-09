#include <proxy/capture_enrichment.hpp>

#include <gtest/gtest.h>

#include <service/cfgapi/cfgapi.hpp>

#include <cstdio>
#include <memory>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace {

struct FileCloser {
    void operator()(FILE* file) const noexcept {
        if(file) std::fclose(file);
    }
};

TEST(CaptureEnrichment, NullCertificateProducesNoIdentity) {
    EXPECT_TRUE(sx::capture::peer_certificate(nullptr).empty());
}

TEST(CaptureEnrichment, CertificateIdentityIsStableAndCompact) {
    std::unique_ptr<FILE, FileCloser> input(
        std::fopen("etc/certs/default/srv-cert.pem", "r"));
    ASSERT_TRUE(input);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
    ASSERT_TRUE(certificate);

    auto const first = sx::capture::peer_certificate(certificate.get());
    auto const second = sx::capture::peer_certificate(certificate.get());
    ASSERT_TRUE(first.contains("sha256"));
    EXPECT_EQ(first["sha256"].get<std::string>().size(), 64U);
    EXPECT_EQ(first["sha256"], second["sha256"]);
    EXPECT_TRUE(first.contains("subject_cn"));
    EXPECT_TRUE(first.contains("issuer_cn"));
    EXPECT_FALSE(first["subject"].get<std::string>().empty());
    EXPECT_FALSE(first["issuer"].get<std::string>().empty());
    EXPECT_FALSE(first["serial_hex"].get<std::string>().empty());
    EXPECT_GT(first["public_key"]["bits"].get<int>(), 0);
    EXPECT_EQ(first["not_before"].get<std::string>().back(), 'Z');
    EXPECT_EQ(first["not_after"].get<std::string>().back(), 'Z');
    EXPECT_FALSE(first.contains("private_key"));
    EXPECT_FALSE(first.contains("pem"));
}

TEST(CaptureEnrichment, CertificateDatesSerialAndAlternativeNamesAreExplicit) {
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    ASSERT_TRUE(certificate);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 42), 1);
    ASSERT_EQ(ASN1_TIME_set_string(X509_getm_notBefore(certificate.get()), "20260102030405Z"), 1);
    ASSERT_EQ(ASN1_TIME_set_string(X509_getm_notAfter(certificate.get()), "20270102030405Z"), 1);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san(
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                           const_cast<char*>("DNS:example.test,DNS:*.example.test,IP:192.0.2.1,IP:2001:db8::1")),
        X509_EXTENSION_free);
    ASSERT_TRUE(san);
    ASSERT_EQ(X509_add_ext(certificate.get(), san.get(), -1), 1);

    auto const result = sx::capture::peer_certificate(certificate.get());
    EXPECT_EQ(result["serial_hex"], "2A");
    EXPECT_EQ(result["not_before"], "2026-01-02T03:04:05Z");
    EXPECT_EQ(result["not_after"], "2027-01-02T03:04:05Z");
    EXPECT_EQ(result["san"]["dns"], nlohmann::json::array({"example.test", "*.example.test"}));
    EXPECT_EQ(result["san"]["ip"], nlohmann::json::array({"192.0.2.1", "2001:db8::1"}));
    EXPECT_FALSE(result.contains("san_truncated"));
}

TEST(CaptureEnrichment, TlsPayloadKeepsIdentityAndSeparatesBothLegs) {
    nlohmann::json identity = {
        {"session_id", "Proxy-1"},
        {"proxy_session_key", "tls_10.0.0.1:1234-1.1.1.1:443"},
    };
    nlohmann::json left = {{"role", "server"}, {"cipher", "LEFT"}};
    nlohmann::json right = {
        {"role", "client"}, {"cipher", "RIGHT"},
        {"verify", {{"ok", true}}},
    };

    auto const payload = sx::capture::tls_payload(
        std::move(identity), "tcp", std::move(left), std::move(right));
    EXPECT_EQ(payload["schema"], "smithproxy.tls.v1");
    EXPECT_EQ(payload["transport"], "tcp");
    EXPECT_EQ(payload["session_id"], "Proxy-1");
    EXPECT_EQ(payload["proxy_session_key"], "tls_10.0.0.1:1234-1.1.1.1:443");
    EXPECT_EQ(payload["L"]["role"], "server");
    EXPECT_EQ(payload["L"]["cipher"], "LEFT");
    EXPECT_EQ(payload["R"]["role"], "client");
    EXPECT_EQ(payload["R"]["cipher"], "RIGHT");
    EXPECT_TRUE(payload["R"]["verify"]["ok"]);
}

TEST(CaptureEnrichment, PayloadGateAndStatisticsImplicationAreExplicit) {
    CfgFactory::capture_automation_t options;

    EXPECT_FALSE(options.metadata_enabled(false));
    EXPECT_FALSE(options.metadata_enabled(true));
    EXPECT_FALSE(options.statistics_enabled(true));

    options.metadata = true;
    EXPECT_FALSE(options.metadata_enabled(false));
    EXPECT_TRUE(options.metadata_enabled(true));
    EXPECT_FALSE(options.statistics_enabled(true));

    options.metadata = false;
    options.statistics = true;
    EXPECT_FALSE(options.metadata_enabled(false));
    EXPECT_TRUE(options.metadata_enabled(true));
    EXPECT_TRUE(options.statistics_enabled(true));
}

} // namespace
