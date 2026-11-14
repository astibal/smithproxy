#include <service/http/jsonize_x509.hpp>
#include <ossl_util.hpp>
#include <openssl/pem.h>
#include <cstdio>
#include <gtest/gtest.h>

#include <service/http/jsonize.hpp>

#include <memory>

TEST(Jsonize, LoadsTypedParametersAndRejectsMissingOrMalformedValues) {
    auto const request = R"({"params":{"name":"alpha","count":42,"enabled":true}})";
    EXPECT_EQ(jsonize::load_json_params<std::string>(request, "name"), "alpha");
    EXPECT_EQ(jsonize::load_json_params<int>(request, "count"), 42);
    EXPECT_EQ(jsonize::load_json_params<bool>(request, "enabled"), true);
    EXPECT_FALSE(jsonize::load_json_params<int>(request, "missing").has_value());
    EXPECT_FALSE(jsonize::load_json_params<int>(request, "name").has_value());
    EXPECT_FALSE(jsonize::load_json_params<int>("not-json", "count").has_value());
}

TEST(Jsonize, StatusResponseUsesExactlyOneStableResultKey) {
    auto const success = jsonize::cfg_status_response({true, "stored"});
    EXPECT_EQ(success, nlohmann::json({{"success", "stored"}}));
    EXPECT_FALSE(success.contains("error"));

    auto const error = jsonize::cfg_status_response({false, "rejected"});
    EXPECT_EQ(error, nlohmann::json({{"error", "rejected"}}));
    EXPECT_FALSE(error.contains("success"));
}

TEST(Jsonize, ConvertsNestedLibconfigIncludingScalarLists) {
    libconfig::Config config;
    config.readString(R"(
        number = 42;
        large = 5000000000L;
        text = "hello";
        ratio = 1.5;
        enabled = true;
        array = [ 1, 2, 3 ];
        list = ( 7, "eight", false, { nested = "value"; } );
        group = { child = 9; };
    )");

    auto const converted = jsonize::from(config.getRoot());
    EXPECT_EQ(converted["number"], "42");
    EXPECT_EQ(converted["large"], "5000000000");
    EXPECT_EQ(converted["text"], "hello");
    EXPECT_EQ(converted["ratio"], "1.5");
    EXPECT_EQ(converted["enabled"], "1");
    EXPECT_EQ(converted["array"], nlohmann::json({"1", "2", "3"}));
    ASSERT_TRUE(converted["list"].is_array());
    EXPECT_EQ(converted["list"][0], "7");
    EXPECT_EQ(converted["list"][1], "eight");
    EXPECT_EQ(converted["list"][2], "0");
    EXPECT_EQ(converted["list"][3]["nested"], "value");
    EXPECT_EQ(converted["group"]["child"], "9");
}

TEST(Jsonize, RejectsNullCertificateAndSerializesSparseCertificateSafely) {
    EXPECT_TRUE(jsonize::from(static_cast<X509 const*>(nullptr), iINF).empty());

    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0), nullptr);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600), nullptr);

    auto const serialized = jsonize::from(certificate.get(), iINF);
    EXPECT_EQ(serialized["cn"], "");
    EXPECT_EQ(serialized["subject"], "");
    EXPECT_EQ(serialized["issuer"], "");
    EXPECT_FALSE(serialized["valid_from"].get<std::string>().empty());
    EXPECT_FALSE(serialized["valid_to"].get<std::string>().empty());
    EXPECT_FALSE(serialized.contains("sigalg"));
    EXPECT_FALSE(serialized.contains("extensions"));
}

TEST(Jsonize, SerializesCertificateNamesAndVerboseMetadata) {
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0), nullptr);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600), nullptr);

    auto* subject = X509_get_subject_name(certificate.get());
    ASSERT_NE(subject, nullptr);
    ASSERT_EQ(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                         reinterpret_cast<unsigned char const*>("example.test"),
                                         -1, -1, 0), 1);
    ASSERT_EQ(X509_set_issuer_name(certificate.get(), subject), 1);

    auto const serialized = jsonize::from(certificate.get(), iDIA);
    EXPECT_EQ(serialized["cn"], "example.test");
    EXPECT_EQ(serialized["subject"], "/CN=example.test");
    EXPECT_EQ(serialized["issuer"], "/CN=example.test");
    EXPECT_TRUE(serialized.contains("extensions"));
}

namespace {

struct X509FileCloser {
    void operator()(FILE* file) const noexcept {
        if(file) std::fclose(file);
    }
};

TEST(CertificateSummary, NullCertificateProducesNoIdentity) {
    EXPECT_TRUE(jsonize::certificate_summary(nullptr).empty());
}

TEST(CertificateSummary, CertificateIdentityIsStableAndCompact) {
    std::unique_ptr<FILE, X509FileCloser> input(
        std::fopen("etc/certs/default/srv-cert.pem", "r"));
    ASSERT_TRUE(input);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
    ASSERT_TRUE(certificate);

    auto const first = jsonize::certificate_summary(certificate.get());
    auto const second = jsonize::certificate_summary(certificate.get());
    ASSERT_TRUE(first.contains("sha256"));
    EXPECT_EQ(SSLFactory::fingerprint(certificate.get()).size(), 40U);
    EXPECT_EQ(SSLFactory::fingerprint(certificate.get()),
              socle::ossl::fingerprint(certificate.get(), EVP_sha1()));
    EXPECT_EQ(first["sha256"], socle::ossl::fingerprint(certificate.get(), EVP_sha256(), socle::ossl::hex_case::upper));
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

TEST(CertificateSummary, CertificateDatesSerialAndAlternativeNamesAreExplicit) {
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

    auto const result = jsonize::certificate_summary(certificate.get());
    EXPECT_EQ(result["serial_hex"], "2A");
    EXPECT_EQ(result["not_before"], "2026-01-02T03:04:05Z");
    EXPECT_EQ(result["not_after"], "2027-01-02T03:04:05Z");
    EXPECT_EQ(result["san"]["dns"], nlohmann::json::array({"example.test", "*.example.test"}));
    EXPECT_EQ(result["san"]["ip"], nlohmann::json::array({"192.0.2.1", "2001:db8::1"}));
    EXPECT_FALSE(result.contains("san_truncated"));
}


} // namespace
