#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <buffer.hpp>
#include <log/logger.hpp>
#include <sslcertval.hpp>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <vector>

namespace {

template <class T, void (*Free)(T*)>
using openssl_ptr = std::unique_ptr<T, decltype(Free)>;

using x509_ptr = openssl_ptr<X509, X509_free>;
using pkey_ptr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;
using store_ptr = openssl_ptr<X509_STORE, X509_STORE_free>;

x509_ptr load_certificate(const std::filesystem::path& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file)
        return {nullptr, X509_free};
    X509* certificate = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    return {certificate, X509_free};
}

pkey_ptr load_key(const std::filesystem::path& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file)
        return {nullptr, EVP_PKEY_free};
    EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return {key, EVP_PKEY_free};
}

std::vector<uint8_t> encode_ocsp(OCSP_RESPONSE* response) {
    const int length = i2d_OCSP_RESPONSE(response, nullptr);
    if (length <= 0)
        return {};
    std::vector<uint8_t> encoded(static_cast<std::size_t>(length));
    unsigned char* output = encoded.data();
    i2d_OCSP_RESPONSE(response, &output);
    return encoded;
}

std::vector<uint8_t> encode_crl(X509_CRL* crl) {
    const int length = i2d_X509_CRL(crl, nullptr);
    if (length <= 0)
        return {};
    std::vector<uint8_t> encoded(static_cast<std::size_t>(length));
    unsigned char* output = encoded.data();
    i2d_X509_CRL(crl, &output);
    return encoded;
}

struct fixture {
    x509_ptr issuer{nullptr, X509_free};
    x509_ptr certificate{nullptr, X509_free};
    pkey_ptr issuer_key{nullptr, EVP_PKEY_free};
    store_ptr store{nullptr, X509_STORE_free};
    std::vector<uint8_t> ocsp_good;
    std::vector<uint8_t> ocsp_mixed;
    std::vector<uint8_t> crl_revoked;

    fixture() {
        Log::init();
        const auto pki = std::filesystem::path(SMITHPROXY_SOURCE_DIR) / "etc/certs/default";
        issuer = load_certificate(pki / "ca-cert.pem");
        certificate = load_certificate(pki / "srv-cert.pem");
        issuer_key = load_key(pki / "ca-key.pem");
        if (!issuer || !certificate || !issuer_key)
            return;

        store.reset(X509_STORE_new());
        if (!store || X509_STORE_add_cert(store.get(), issuer.get()) != 1) {
            store.reset();
            return;
        }
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(store.get()), 1583000000);
        ocsp_good = make_ocsp({{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});

        x509_ptr other(X509_dup(certificate.get()), X509_free);
        if (other) {
            ASN1_INTEGER_set(X509_get_serialNumber(other.get()), 0x424242);
            ocsp_mixed = make_ocsp({{certificate.get(), V_OCSP_CERTSTATUS_GOOD},
                                    {other.get(), V_OCSP_CERTSTATUS_REVOKED}});
        }
        crl_revoked = make_crl();
    }

    std::vector<uint8_t> make_ocsp(const std::vector<std::pair<X509*, int>>& entries) {
        OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
        if (!basic)
            return {};
        for (const auto& [cert, status] : entries) {
            OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha1(), cert, issuer.get());
            ASN1_TIME* this_update = ASN1_TIME_adj(nullptr, time(nullptr), 0, -60);
            ASN1_TIME* next_update = ASN1_TIME_adj(nullptr, time(nullptr), 0, 3600);
            ASN1_TIME* revoked_at = status == V_OCSP_CERTSTATUS_REVOKED
                                      ? ASN1_TIME_adj(nullptr, time(nullptr), 0, -120)
                                      : nullptr;
            const bool ok = id && this_update && next_update &&
                OCSP_basic_add1_status(basic, id, status, OCSP_REVOKED_STATUS_UNSPECIFIED,
                                       revoked_at, this_update, next_update);
            OCSP_CERTID_free(id);
            ASN1_TIME_free(this_update);
            ASN1_TIME_free(next_update);
            ASN1_TIME_free(revoked_at);
            if (!ok) {
                OCSP_BASICRESP_free(basic);
                return {};
            }
        }
        if (OCSP_basic_sign(basic, issuer.get(), issuer_key.get(), EVP_sha256(), nullptr, 0) != 1) {
            OCSP_BASICRESP_free(basic);
            return {};
        }
        OCSP_RESPONSE* response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
        OCSP_BASICRESP_free(basic);
        const auto encoded = encode_ocsp(response);
        OCSP_RESPONSE_free(response);
        return encoded;
    }

    std::vector<uint8_t> make_crl() {
        X509_CRL* crl = X509_CRL_new();
        if (!crl)
            return {};
        X509_CRL_set_version(crl, 1);
        X509_CRL_set_issuer_name(crl, X509_get_subject_name(issuer.get()));
        ASN1_TIME* last = ASN1_TIME_adj(nullptr, time(nullptr), 0, -60);
        ASN1_TIME* next = ASN1_TIME_adj(nullptr, time(nullptr), 1, 0);
        X509_CRL_set1_lastUpdate(crl, last);
        X509_CRL_set1_nextUpdate(crl, next);
        ASN1_TIME_free(last);
        ASN1_TIME_free(next);

        X509_REVOKED* revoked = X509_REVOKED_new();
        ASN1_INTEGER* serial = ASN1_INTEGER_dup(X509_get0_serialNumber(certificate.get()));
        ASN1_TIME* when = ASN1_TIME_adj(nullptr, time(nullptr), 0, -30);
        if (!revoked || !serial || !when ||
            X509_REVOKED_set_serialNumber(revoked, serial) != 1 ||
            X509_REVOKED_set_revocationDate(revoked, when) != 1 ||
            X509_CRL_add0_revoked(crl, revoked) != 1) {
            X509_REVOKED_free(revoked);
        }
        ASN1_INTEGER_free(serial);
        ASN1_TIME_free(when);
        X509_CRL_sort(crl);
        X509_CRL_sign(crl, issuer_key.get(), EVP_sha256());
        const auto encoded = encode_crl(crl);
        X509_CRL_free(crl);
        return encoded;
    }
};

fixture& get_fixture() {
    static fixture value;
    return value;
}

std::vector<uint8_t> mutate(std::vector<uint8_t> value, const uint8_t* data, std::size_t size) {
    if (value.empty())
        return value;
    for (std::size_t i = 1; i + 1 < size; i += 2) {
        const std::size_t position =
            (static_cast<std::size_t>(data[i]) * 257U + data[i + 1]) % value.size();
        value[position] ^= data[i + 1];
    }
    return value;
}

void exercise_ocsp(const std::vector<uint8_t>& encoded, fixture& f) {
    const unsigned char* input = encoded.data();
    OCSP_RESPONSE* response = d2i_OCSP_RESPONSE(nullptr, &input, encoded.size());
    if (!response)
        return;
    const auto result = inet::ocsp::ocsp_verify_response(
        response, f.certificate.get(), f.issuer.get(), f.store.get());
    if (result.revoked < -1 || result.revoked > 1)
        __builtin_trap();
    OCSP_RESPONSE_free(response);
}

void exercise_crl(const std::vector<uint8_t>& encoded, fixture& f) {
    buffer bytes;
    bytes.assign(const_cast<uint8_t*>(encoded.data()), encoded.size(), encoded.size(), false);
    X509_CRL* crl = inet::crl::crl_from_bytes(bytes);
    if (!crl)
        return;
    const int result = inet::crl::crl_is_revoked_by(f.certificate.get(), f.issuer.get(), crl);
    if (result < -1 || result > 1)
        __builtin_trap();
    X509_CRL_free(crl);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (!data || size == 0 || size > 65536)
        return 0;
    auto& f = get_fixture();
    if (!f.issuer || !f.certificate || !f.issuer_key || !f.store)
        return 0;

    switch (data[0] % 4) {
        case 0: exercise_ocsp(mutate(f.ocsp_good, data, size), f); break;
        case 1: exercise_ocsp(mutate(f.ocsp_mixed, data, size), f); break;
        case 2: exercise_crl(mutate(f.crl_revoked, data, size), f); break;
        default: {
            std::vector<uint8_t> raw(data + 1, data + size);
            exercise_ocsp(raw, f);
            exercise_crl(raw, f);
            break;
        }
    }
    return 0;
}
