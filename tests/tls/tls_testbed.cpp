#include <gtest/gtest.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <sslcertstore.hpp>
#include <sslcertval.hpp>
#include <log/logger.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace {

using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using crl_ptr = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>;
using ocsp_response_ptr = std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)>;
using x509_store_ptr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;

x509_ptr load_certificate(const std::filesystem::path& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file)
        return {nullptr, X509_free};
    X509* certificate = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    return {certificate, X509_free};
}

pkey_ptr load_private_key(const std::filesystem::path& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file)
        return {nullptr, EVP_PKEY_free};
    EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return {key, EVP_PKEY_free};
}

pkey_ptr generate_rsa_key() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* key = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0 ||
        EVP_PKEY_keygen(context.get(), &key) <= 0)
        return {nullptr, EVP_PKEY_free};
    return {key, EVP_PKEY_free};
}

crl_ptr make_crl(X509* issuer, EVP_PKEY* issuer_key, X509* revoked_certificate) {
    crl_ptr crl(X509_CRL_new(), X509_CRL_free);
    if (!crl || X509_CRL_set_version(crl.get(), 1) != 1 ||
        X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer)) != 1)
        return {nullptr, X509_CRL_free};

    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> last_update(
        ASN1_TIME_adj(nullptr, time(nullptr), 0, -60), ASN1_TIME_free);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> next_update(
        ASN1_TIME_adj(nullptr, time(nullptr), 1, 0), ASN1_TIME_free);
    if (!last_update || !next_update ||
        X509_CRL_set1_lastUpdate(crl.get(), last_update.get()) != 1 ||
        X509_CRL_set1_nextUpdate(crl.get(), next_update.get()) != 1)
        return {nullptr, X509_CRL_free};

    if (revoked_certificate) {
        X509_REVOKED* revoked = X509_REVOKED_new();
        ASN1_INTEGER* serial = ASN1_INTEGER_dup(X509_get0_serialNumber(revoked_certificate));
        ASN1_TIME* revoked_at = ASN1_TIME_adj(nullptr, time(nullptr), 0, -30);
        if (!revoked || !serial || !revoked_at ||
            X509_REVOKED_set_serialNumber(revoked, serial) != 1 ||
            X509_REVOKED_set_revocationDate(revoked, revoked_at) != 1 ||
            X509_CRL_add0_revoked(crl.get(), revoked) != 1) {
            X509_REVOKED_free(revoked);
            ASN1_INTEGER_free(serial);
            ASN1_TIME_free(revoked_at);
            return {nullptr, X509_CRL_free};
        }
        ASN1_INTEGER_free(serial);
        ASN1_TIME_free(revoked_at);
        X509_CRL_sort(crl.get());
    }

    if (X509_CRL_sign(crl.get(), issuer_key, EVP_sha256()) <= 0)
        return {nullptr, X509_CRL_free};
    return crl;
}

struct ocsp_entry {
    X509* certificate;
    int status;
};

ocsp_response_ptr make_ocsp_response(X509* issuer, EVP_PKEY* issuer_key,
                                     const std::vector<ocsp_entry>& entries,
                                     int this_update_offset = -60,
                                     int next_update_offset = 3600) {
    OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
    if (!basic)
        return {nullptr, OCSP_RESPONSE_free};

    bool valid = true;
    for (const auto& entry : entries) {
        OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha1(), entry.certificate, issuer);
        ASN1_TIME* this_update = ASN1_TIME_adj(nullptr, time(nullptr), 0, this_update_offset);
        ASN1_TIME* next_update = ASN1_TIME_adj(nullptr, time(nullptr), 0, next_update_offset);
        ASN1_TIME* revoked_at = entry.status == V_OCSP_CERTSTATUS_REVOKED
                                  ? ASN1_TIME_adj(nullptr, time(nullptr), 0, -120)
                                  : nullptr;
        if (!id || !this_update || !next_update ||
            !OCSP_basic_add1_status(basic, id, entry.status,
                                    OCSP_REVOKED_STATUS_KEYCOMPROMISE,
                                    revoked_at, this_update, next_update))
            valid = false;
        OCSP_CERTID_free(id);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        ASN1_TIME_free(revoked_at);
        if (!valid)
            break;
    }

    if (!valid || OCSP_basic_sign(basic, issuer, issuer_key, EVP_sha256(), nullptr, 0) != 1) {
        OCSP_BASICRESP_free(basic);
        return {nullptr, OCSP_RESPONSE_free};
    }
    OCSP_RESPONSE* response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    OCSP_BASICRESP_free(basic);
    return {response, OCSP_RESPONSE_free};
}

x509_store_ptr make_test_store(X509* trusted_certificate) {
    x509_store_ptr store(X509_STORE_new(), X509_STORE_free);
    if (!store || X509_STORE_add_cert(store.get(), trusted_certificate) != 1)
        return {nullptr, X509_STORE_free};
    // The repository fixture was intentionally short-lived in 2020. Pinning
    // verification inside that validity window tests trust, not wall-clock age.
    X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(store.get()), 1583000000);
    return store;
}

int select_h2(SSL*, const unsigned char** out, unsigned char* out_length,
              const unsigned char* input, unsigned int input_length, void*) {
    static constexpr unsigned char supported[] = {2, 'h', '2'};
    return SSL_select_next_proto(
               const_cast<unsigned char**>(out), out_length,
               supported, sizeof(supported), input, input_length) == OPENSSL_NPN_NEGOTIATED
               ? SSL_TLSEXT_ERR_OK
               : SSL_TLSEXT_ERR_NOACK;
}

struct handshake_result {
    bool complete = false;
    std::string sni;
    std::string alpn;
    bool application_data_ok = false;
};

handshake_result memory_handshake(X509* certificate, EVP_PKEY* key, int version,
                                  bool send_sni, int alpn_mode, std::size_t payload_size) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> server_ctx(
        SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!server_ctx || !client_ctx)
        return {};

    if (SSL_CTX_use_certificate(server_ctx.get(), certificate) != 1 ||
        SSL_CTX_use_PrivateKey(server_ctx.get(), key) != 1 ||
        SSL_CTX_check_private_key(server_ctx.get()) != 1)
        return {};

    SSL_CTX_set_min_proto_version(server_ctx.get(), version);
    SSL_CTX_set_max_proto_version(server_ctx.get(), version);
    SSL_CTX_set_min_proto_version(client_ctx.get(), version);
    SSL_CTX_set_max_proto_version(client_ctx.get(), version);
    SSL_CTX_set_alpn_select_cb(server_ctx.get(), select_h2, nullptr);

    std::unique_ptr<SSL, decltype(&SSL_free)> client(SSL_new(client_ctx.get()), SSL_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> server(SSL_new(server_ctx.get()), SSL_free);
    if (!client || !server)
        return {};

    BIO* client_bio = nullptr;
    BIO* server_bio = nullptr;
    if (BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) != 1)
        return {};
    SSL_set_bio(client.get(), client_bio, client_bio);
    SSL_set_bio(server.get(), server_bio, server_bio);
    SSL_set_connect_state(client.get());
    SSL_set_accept_state(server.get());

    static constexpr unsigned char h2_first[] = {
        2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    static constexpr unsigned char http1_only[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    static constexpr unsigned char http1_first[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1', 2, 'h', '2'};
    if (send_sni)
        SSL_set_tlsext_host_name(client.get(), "tls-test.smithproxy.invalid");
    if (alpn_mode == 1)
        SSL_set_alpn_protos(client.get(), h2_first, sizeof(h2_first));
    else if (alpn_mode == 2)
        SSL_set_alpn_protos(client.get(), http1_only, sizeof(http1_only));
    else if (alpn_mode == 3)
        SSL_set_alpn_protos(client.get(), http1_first, sizeof(http1_first));

    bool client_done = false;
    bool server_done = false;
    for (int round = 0; round < 1000 && !(client_done && server_done); ++round) {
        if (!client_done) {
            const int result = SSL_do_handshake(client.get());
            client_done = result == 1;
            if (!client_done) {
                const int error = SSL_get_error(client.get(), result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return {};
            }
        }
        if (!server_done) {
            const int result = SSL_do_handshake(server.get());
            server_done = result == 1;
            if (!server_done) {
                const int error = SSL_get_error(server.get(), result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return {};
            }
        }
    }

    const char* requested_sni = SSL_get_servername(server.get(), TLSEXT_NAMETYPE_host_name);
    const unsigned char* selected_alpn = nullptr;
    unsigned int selected_alpn_length = 0;
    SSL_get0_alpn_selected(client.get(), &selected_alpn, &selected_alpn_length);

    bool application_data_ok = false;
    if (client_done && server_done) {
        const std::string payload(payload_size, 'C');
        if (payload.empty()) {
            application_data_ok = true;
        } else {
            const int written = SSL_write(client.get(), payload.data(), payload.size());
            std::string received(payload.size(), '\0');
            const int read = SSL_read(server.get(), received.data(), received.size());
            application_data_ok = written == static_cast<int>(payload.size()) &&
                                  read == written && received == payload;
        }
    }
    return {
        client_done && server_done,
        requested_sni ? requested_sni : "",
        std::string(reinterpret_cast<const char*>(selected_alpn), selected_alpn_length),
        application_data_ok};
}

class TLSIntegration : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Log::init();
        fixture_path_ = std::filesystem::temp_directory_path() /
                        ("smithproxy-tls-testbed-" + std::to_string(getpid()));
        std::filesystem::remove_all(fixture_path_);
        std::filesystem::create_directories(fixture_path_);
        std::filesystem::copy(
            std::filesystem::path(SMITHPROXY_SOURCE_DIR) / "etc/certs/default",
            fixture_path_, std::filesystem::copy_options::recursive);

        auto& factory = SSLFactory::factory();
        factory.certs_path() = fixture_path_.string() + "/";
        factory.ca_file() = (fixture_path_ / "ca-cert.pem").string();
        factory.ca_path().clear();
        factory.init();
    }

    static void TearDownTestSuite() {
        std::filesystem::remove_all(fixture_path_);
    }

    static x509_ptr upstream_certificate() {
        return load_certificate(fixture_path_ / "srv-cert.pem");
    }

    static std::filesystem::path fixture_path_;
};

std::filesystem::path TLSIntegration::fixture_path_;

TEST_F(TLSIntegration, SpoofPreservesIdentityAndUsesLocalCA) {
    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);

    auto spoofed = SSLFactory::factory().spoof(upstream.get());
    ASSERT_TRUE(spoofed.has_value());
    ASSERT_NE(spoofed->chain.cert, nullptr);
    ASSERT_NE(spoofed->chain.key, nullptr);

    EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(upstream.get()),
                            X509_get_subject_name(spoofed->chain.cert)), 0);
    EXPECT_EQ(SSLFactory::get_sans(upstream.get()),
              SSLFactory::get_sans(spoofed->chain.cert));
    EXPECT_EQ(X509_check_private_key(spoofed->chain.cert, spoofed->chain.key), 1);

    auto ca = load_certificate(fixture_path_ / "ca-cert.pem");
    ASSERT_NE(ca, nullptr);
    EXPECT_EQ(X509_NAME_cmp(X509_get_issuer_name(spoofed->chain.cert),
                            X509_get_subject_name(ca.get())), 0);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ca_key(
        X509_get_pubkey(ca.get()), EVP_PKEY_free);
    ASSERT_NE(ca_key, nullptr);
    EXPECT_EQ(X509_verify(spoofed->chain.cert, ca_key.get()), 1);

    X509_free(spoofed->chain.cert);
}

TEST_F(TLSIntegration, SpoofAddsRequestedSAN) {
    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);
    std::vector<std::string> additional_sans = {"DNS:tls-test.smithproxy.invalid"};

    auto spoofed = SSLFactory::factory().spoof(upstream.get(), false, &additional_sans);
    ASSERT_TRUE(spoofed.has_value());
    const auto sans = SSLFactory::get_sans(spoofed->chain.cert);
    EXPECT_NE(std::find(sans.begin(), sans.end(), additional_sans.front()), sans.end());

    X509_free(spoofed->chain.cert);
}

TEST_F(TLSIntegration, CRLReportsRevokedSerial) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    auto crl = make_crl(issuer.get(), issuer_key.get(), certificate.get());
    ASSERT_NE(crl, nullptr);

    EXPECT_EQ(inet::crl::crl_is_revoked_by(certificate.get(), issuer.get(), crl.get()), 1);
}

TEST_F(TLSIntegration, CRLReportsGoodSerial) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    auto crl = make_crl(issuer.get(), issuer_key.get(), nullptr);
    ASSERT_NE(crl, nullptr);

    EXPECT_EQ(inet::crl::crl_is_revoked_by(certificate.get(), issuer.get(), crl.get()), 0);
}

TEST_F(TLSIntegration, CRLRejectsWrongIssuer) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto wrong_key = generate_rsa_key();
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(wrong_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    auto crl = make_crl(issuer.get(), wrong_key.get(), certificate.get());
    ASSERT_NE(crl, nullptr);

    EXPECT_EQ(inet::crl::crl_is_revoked_by(certificate.get(), issuer.get(), crl.get()), -1);
}

TEST_F(TLSIntegration, OCSPUrlsContainOnlyCertificateEntries) {
    auto certificate = upstream_certificate();
    ASSERT_NE(certificate, nullptr);
    X509V3_CTX context{};
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, nullptr, certificate.get(), nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(
        nullptr, &context, NID_info_access,
        const_cast<char*>("OCSP;URI:http://ocsp-one.invalid/status,"
                          "OCSP;URI:http://ocsp-two.invalid/status"));
    ASSERT_NE(extension, nullptr);
    ASSERT_EQ(X509_add_ext(certificate.get(), extension, -1), 1);
    X509_EXTENSION_free(extension);

    EXPECT_EQ(inet::ocsp::ocsp_urls(certificate.get()),
              (std::vector<std::string>{"http://ocsp-one.invalid/status",
                                        "http://ocsp-two.invalid/status"}));
}

TEST_F(TLSIntegration, OCSPMatchingEntryCannotBeOverriddenByDifferentCertificate) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);

    x509_ptr different_certificate(X509_dup(certificate.get()), X509_free);
    ASSERT_NE(different_certificate, nullptr);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(different_certificate.get()), 0x123456), 1);

    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD},
         {different_certificate.get(), V_OCSP_CERTSTATUS_REVOKED}});
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);

    const auto result = inet::ocsp::ocsp_verify_response(
        response.get(), certificate.get(), issuer.get(), store.get());
    EXPECT_EQ(result.revoked, 0);
}

using ocsp_parameters = std::tuple<int, int, int, int>;

class OCSPStatusMatrix : public TLSIntegration,
                         public ::testing::WithParamInterface<ocsp_parameters> {};

TEST_P(OCSPStatusMatrix, ReturnsStatusOnlyForCurrentSignedResponse) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);

    const auto [status, this_update_offset, next_update_offset, expected] = GetParam();
    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(), {{certificate.get(), status}},
        this_update_offset, next_update_offset);
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);

    const auto result = inet::ocsp::ocsp_verify_response(
        response.get(), certificate.get(), issuer.get(), store.get());
    EXPECT_EQ(result.revoked, expected);
    EXPECT_GT(result.ttl, 0);
}

std::string ocsp_status_name(const ::testing::TestParamInfo<ocsp_parameters>& parameter) {
    switch (parameter.index) {
        case 0: return "Good";
        case 1: return "Revoked";
        case 2: return "Unknown";
        case 3: return "Expired";
        case 4: return "Future";
        default: return "Case" + std::to_string(parameter.index);
    }
}

INSTANTIATE_TEST_SUITE_P(
    SignedResponses, OCSPStatusMatrix,
    ::testing::Values(
        ocsp_parameters{V_OCSP_CERTSTATUS_GOOD, -60, 3600, 0},
        ocsp_parameters{V_OCSP_CERTSTATUS_REVOKED, -60, 3600, 1},
        ocsp_parameters{V_OCSP_CERTSTATUS_UNKNOWN, -60, 3600, -1},
        ocsp_parameters{V_OCSP_CERTSTATUS_GOOD, -7200, -3600, -1},
        ocsp_parameters{V_OCSP_CERTSTATUS_GOOD, 3600, 7200, -1}),
    ocsp_status_name);

TEST_F(TLSIntegration, OCSPResponseForDifferentCertificateIsUnknown) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    x509_ptr different_certificate(X509_dup(certificate.get()), X509_free);
    ASSERT_NE(different_certificate, nullptr);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(different_certificate.get()), 0x654321), 1);

    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{different_certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  response.get(), certificate.get(), issuer.get(), store.get()).revoked,
              -1);
}

TEST_F(TLSIntegration, OCSPRejectsNullAndResponderErrors) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(nullptr, certificate.get(), issuer.get()).revoked, -1);

    ocsp_response_ptr error_response(
        OCSP_response_create(OCSP_RESPONSE_STATUS_TRYLATER, nullptr), OCSP_RESPONSE_free);
    ASSERT_NE(error_response, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  error_response.get(), certificate.get(), issuer.get()).revoked,
              -1);
}

TEST_F(TLSIntegration, OCSPRejectsResponseWithWrongSignature) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);

    auto valid_response = make_ocsp_response(
        issuer.get(), issuer_key.get(), {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(valid_response, nullptr);
    OCSP_BASICRESP* basic = OCSP_response_get1_basic(valid_response.get());
    ASSERT_NE(basic, nullptr);
    const ASN1_OCTET_STRING* signature = OCSP_resp_get0_signature(basic);
    ASSERT_NE(signature, nullptr);
    ASSERT_GT(ASN1_STRING_length(signature), 0);
    auto* signature_data = const_cast<unsigned char*>(ASN1_STRING_get0_data(signature));
    signature_data[0] ^= 0x01;
    ocsp_response_ptr response(
        OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic), OCSP_RESPONSE_free);
    OCSP_BASICRESP_free(basic);
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  response.get(), certificate.get(), issuer.get(), store.get()).revoked,
              -1);
}

using handshake_parameters = std::tuple<int, bool, int, std::size_t>;

class TLSHandshakeMatrix : public TLSIntegration,
                           public ::testing::WithParamInterface<handshake_parameters> {};

std::string handshake_name(
    const ::testing::TestParamInfo<handshake_parameters>& parameter) {
    const auto [version, send_sni, alpn_mode, payload_size] = parameter.param;
    static constexpr const char* alpn_names[] = {"NoALPN", "H2First", "HTTP1Only", "HTTP1First"};
    return std::string(version == TLS1_3_VERSION ? "TLS13" : "TLS12") +
           (send_sni ? "_SNI_" : "_NoSNI_") + alpn_names[alpn_mode] +
           "_Payload" + std::to_string(payload_size);
}

TEST_P(TLSHandshakeMatrix, SpoofedCertificateCompletesNegotiationAndDataTransfer) {
    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);
    auto spoofed = SSLFactory::factory().spoof(upstream.get());
    ASSERT_TRUE(spoofed.has_value());

    const auto [version, send_sni, alpn_mode, payload_size] = GetParam();
    const auto result = memory_handshake(spoofed->chain.cert, spoofed->chain.key,
                                         version, send_sni, alpn_mode, payload_size);
    EXPECT_TRUE(result.complete);
    EXPECT_EQ(result.sni, send_sni ? "tls-test.smithproxy.invalid" : "");
    EXPECT_EQ(result.alpn, alpn_mode == 1 || alpn_mode == 3 ? "h2" : "");
    EXPECT_TRUE(result.application_data_ok);

    X509_free(spoofed->chain.cert);
}

INSTANTIATE_TEST_SUITE_P(
    TLS12AndTLS13, TLSHandshakeMatrix,
    ::testing::Combine(
        ::testing::Values(TLS1_2_VERSION, TLS1_3_VERSION),
        ::testing::Bool(),
        ::testing::Values(0, 1, 2, 3),
        ::testing::Values(std::size_t{0}, std::size_t{1}, std::size_t{4096})),
    handshake_name);

} // namespace
