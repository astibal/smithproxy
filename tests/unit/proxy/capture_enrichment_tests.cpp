#include <proxy/capture_enrichment.hpp>

#include <gtest/gtest.h>

#include <service/cfgapi/cfgapi.hpp>

#include <cstdio>
#include <memory>
#include <openssl/pem.h>

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
    EXPECT_EQ(first.size(), 3U);
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
