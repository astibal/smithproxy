#include <proxy/capture_enrichment.hpp>

#include <array>
#include <openssl/evp.h>

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
