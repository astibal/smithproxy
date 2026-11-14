#include "jsonize_x509.hpp"

#include <ossl_util.hpp>
#include <log/logan.hpp>

namespace jsonize {

nlohmann::json from(X509 const* certificate, int verbosity) {
    nlohmann::json result;
    if(!certificate) return result;
    namespace ossl = socle::ossl;
    result["cn"] = ossl::common_name(X509_get_subject_name(certificate));
    result["subject"] = ossl::name_oneline(X509_get_subject_name(certificate));
    result["issuer"] = ossl::name_oneline(X509_get_issuer_name(certificate));
    result["valid_from"] = ossl::time_text(X509_get0_notBefore(certificate));
    result["valid_to"] = ossl::time_text(X509_get0_notAfter(certificate));
    if(verbosity > iINF) {
        auto signature = ossl::signature_algorithm(certificate);
        if(!signature.empty()) result["sigalg"] = std::move(signature);
        result["extensions"] = ossl::extensions_text(certificate);
    }
    return result;
}

nlohmann::json certificate_summary(X509 const* certificate) {
    nlohmann::json result;
    if(!certificate) return result;
    namespace ossl = socle::ossl;
    auto digest = ossl::fingerprint(certificate, EVP_sha256(), ossl::hex_case::upper);
    if(!digest.empty()) result["sha256"] = std::move(digest);
    auto subject_cn = ossl::common_name(X509_get_subject_name(certificate));
    auto issuer_cn = ossl::common_name(X509_get_issuer_name(certificate));
    if(!subject_cn.empty()) result["subject_cn"] = std::move(subject_cn);
    if(!issuer_cn.empty()) result["issuer_cn"] = std::move(issuer_cn);
    result["subject"] = ossl::distinguished_name(X509_get_subject_name(certificate));
    result["issuer"] = ossl::distinguished_name(X509_get_issuer_name(certificate));
    result["not_before"] = ossl::time_iso8601(X509_get0_notBefore(certificate));
    result["not_after"] = ossl::time_iso8601(X509_get0_notAfter(certificate));
    auto serial = ossl::serial_hex(certificate);
    if(!serial.empty()) result["serial_hex"] = std::move(serial);
    auto key = ossl::public_key(certificate);
    if(key.present) result["public_key"] = {{"algorithm", key.algorithm}, {"bits", key.bits}};
    auto names = ossl::alternative_names(certificate, {256, true, true});
    if(names.present) {
        auto dns = nlohmann::json::array();
        auto ips = nlohmann::json::array();
        for(auto& name : names.names)
            (name.type == ossl::alternative_name_type::dns ? dns : ips).push_back(std::move(name.value));
        result["san"] = {{"dns", std::move(dns)}, {"ip", std::move(ips)}};
    }
    if(names.truncated) result["san_truncated"] = true;
    return result;
}

} // namespace jsonize
