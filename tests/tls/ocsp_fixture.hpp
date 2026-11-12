#pragma once
#include <openssl/ocsp.h>
#include <memory>
#include <vector>
#include <array>
#include <tuple>
#include <ctime>

namespace test_pki {
using ocsp_response_ptr = std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)>;
struct ocsp_entry {
    X509* certificate;
    int status;
};

inline ocsp_response_ptr make_ocsp_response(X509* issuer, EVP_PKEY* issuer_key,
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

using ocsp_parameters = std::tuple<int, int, int, int>;
inline const std::array<ocsp_parameters, 5> ocsp_cases {{
    {V_OCSP_CERTSTATUS_GOOD, -60, 3600, 0},
    {V_OCSP_CERTSTATUS_REVOKED, -60, 3600, 1},
    {V_OCSP_CERTSTATUS_UNKNOWN, -60, 3600, -1},
    {V_OCSP_CERTSTATUS_GOOD, -7200, -3600, -1},
    {V_OCSP_CERTSTATUS_GOOD, 3600, 7200, -1}
}};
} // namespace test_pki
