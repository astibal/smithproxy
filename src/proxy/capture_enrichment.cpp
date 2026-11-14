#include <proxy/capture_enrichment.hpp>

#include <array>
#include <ctime>
#include <memory>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include <display.hpp>

namespace sx::capture {

namespace {

std::string common_name(X509_NAME* name) {
    if(!name) return {};
    std::array<char, 512> value{};
    return X509_NAME_get_text_by_NID(
               name, NID_commonName, value.data(), value.size() - 1) < 0
           ? std::string{} : std::string(value.data());
}

// Render complete distinguished names without confusing embedded separators
// with field boundaries. The JSON remains descriptive, not a trust decision.
std::string distinguished_name(X509_NAME* name) {
    if(!name) return {};
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
    if(!output || X509_NAME_print_ex(output.get(), name, 0, XN_FLAG_RFC2253) < 0)
        return {};
    char* bytes = nullptr;
    auto const size = BIO_get_mem_data(output.get(), &bytes);
    return size > 0 ? std::string(bytes, static_cast<size_t>(size)) : std::string{};
}

std::string certificate_time(ASN1_TIME const* time) {
    std::tm utc{};
    if(!time || ASN1_TIME_to_tm(time, &utc) != 1) return {};
    std::array<char, 32> text{};
    if(std::strftime(text.data(), text.size(), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0)
        return {};
    return text.data();
}

void add_alternative_names(nlohmann::json& result, X509 const* certificate) {
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)),
        GENERAL_NAMES_free);
    if(!names) return;

    auto dns = nlohmann::json::array();
    auto ips = nlohmann::json::array();
    auto const count = sk_GENERAL_NAME_num(names.get());
    // Certificate extensions are untrusted; bound the exported diagnostic list.
    constexpr int maximum_names = 256;
    for(int i = 0; i < count && i < maximum_names; ++i) {
        auto const* name = sk_GENERAL_NAME_value(names.get(), i);
        if(!name) continue;
        if(name->type == GEN_DNS) {
            auto const* value = name->d.dNSName;
            auto const size = ASN1_STRING_length(value);
            auto const* bytes = ASN1_STRING_get0_data(value);
            // IA5 DNS names must be ASCII and must not contain embedded NULs.
            bool valid = size > 0;
            for(int j = 0; valid && j < size; ++j) valid = bytes[j] > 0 && bytes[j] < 128;
            if(valid) dns.push_back(std::string(reinterpret_cast<char const*>(bytes), size));
            continue;
        }
        if(name->type != GEN_IPADD) continue;
        auto const size = ASN1_STRING_length(name->d.iPAddress);
        if(size != 4 && size != 16) continue;
        std::array<char, INET6_ADDRSTRLEN> address{};
        if(inet_ntop(size == 4 ? AF_INET : AF_INET6,
                     ASN1_STRING_get0_data(name->d.iPAddress), address.data(), address.size()))
            ips.push_back(address.data());
    }
    result["san"] = {{"dns", std::move(dns)}, {"ip", std::move(ips)}};
    if(count > maximum_names) result["san_truncated"] = true;
}

} // namespace

nlohmann::json peer_certificate(X509 const* certificate) {
    nlohmann::json result;
    if(!certificate) return result;

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    if(X509_digest(certificate, EVP_sha256(), digest.data(), &digest_size) == 1) {
        result["sha256"] = hex_print(digest.data(), digest_size);
    }

    auto subject_cn = common_name(X509_get_subject_name(certificate));
    auto issuer_cn = common_name(X509_get_issuer_name(certificate));
    if(!subject_cn.empty()) result["subject_cn"] = std::move(subject_cn);
    if(!issuer_cn.empty()) result["issuer_cn"] = std::move(issuer_cn);
    result["subject"] = distinguished_name(X509_get_subject_name(certificate));
    result["issuer"] = distinguished_name(X509_get_issuer_name(certificate));
    result["not_before"] = certificate_time(X509_get0_notBefore(certificate));
    result["not_after"] = certificate_time(X509_get0_notAfter(certificate));

    std::unique_ptr<BIGNUM, decltype(&BN_free)> serial(
        ASN1_INTEGER_to_BN(X509_get0_serialNumber(certificate), nullptr), BN_free);
    if(serial) {
        char* hex = BN_bn2hex(serial.get());
        if(hex) result["serial_hex"] = hex;
        OPENSSL_free(hex);
    }
    // Borrowed public key; neither private key material nor certificate DER is exported.
    if(auto* key = X509_get0_pubkey(certificate); key) {
        auto const* algorithm = OBJ_nid2sn(EVP_PKEY_base_id(key));
        result["public_key"] = {{"algorithm", algorithm ? algorithm : "unknown"},
                                {"bits", EVP_PKEY_bits(key)}};
    }
    add_alternative_names(result, certificate);
    return result;
}

nlohmann::json tls_payload(nlohmann::json identity, std::string transport,
                           nlohmann::json left, nlohmann::json right) {
    identity["schema"] = "smithproxy.tls.v1";
    identity["transport"] = std::move(transport);
    identity["L"] = std::move(left);
    identity["R"] = std::move(right);
    return identity;
}

} // namespace sx::capture
