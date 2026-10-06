#include "jsonize.hpp"

namespace jsonize {

namespace {

constexpr size_t buffer_size = 512;

std::string name_oneline(X509_NAME const* name) {
    if (name == nullptr)
        return {};

    char buffer[buffer_size]{};
    return X509_NAME_oneline(name, buffer, sizeof(buffer) - 1) == nullptr
           ? std::string{} : std::string(buffer);
}

std::string common_name(X509_NAME const* name) {
    if (name == nullptr)
        return {};

    char buffer[buffer_size]{};
    return X509_NAME_get_text_by_NID(name, NID_commonName, buffer,
                                     sizeof(buffer) - 1) < 0
           ? std::string{} : std::string(buffer);
}

std::string asn1_time(ASN1_TIME* value) {
    if (value == nullptr)
        return {};

    char buffer[buffer_size]{};
    SSLFactory::convert_ASN1TIME(value, buffer, sizeof(buffer) - 1);
    return buffer;
}

} // namespace

nlohmann::json from(X509 const* certificate, int verbosity) {
    nlohmann::json result;
    if (certificate == nullptr)
        return result;

    result["cn"] = common_name(X509_get_subject_name(certificate));
    result["subject"] = name_oneline(X509_get_subject_name(certificate));
    result["issuer"] = name_oneline(X509_get_issuer_name(certificate));
    result["valid_from"] = asn1_time(X509_get_notBefore(certificate));
    result["valid_to"] = asn1_time(X509_get_notAfter(certificate));

    if (verbosity > iINF) {
#ifdef USE_OPENSSL11
        auto const signature_nid = X509_get_signature_type(certificate);
#else
        auto const signature_nid = OBJ_obj2nid(certificate->cert_info->key->algor->algorithm);
#endif
        if (auto const* signature = OBJ_nid2ln(signature_nid); signature != nullptr)
            result["sigalg"] = signature;

#ifdef USE_OPENSSL11
        BIO* extension_bio = BIO_new(BIO_s_mem());
        if (extension_bio != nullptr) {
            X509V3_extensions_print(extension_bio, nullptr,
                                    X509_get0_extensions(certificate), 0, 0);
            BUF_MEM* contents = nullptr;
            BIO_get_mem_ptr(extension_bio, &contents);
            if (contents != nullptr)
                result["extensions"] = contents->data == nullptr
                                       ? std::string{}
                                       : std::string(contents->data, contents->length);
            BIO_free(extension_bio);
        }
#endif
    }

    return result;
}

} // namespace jsonize
