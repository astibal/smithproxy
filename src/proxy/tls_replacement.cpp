// Shared TLS warning content and scoped browser exceptions for H1/H2/H3.
// Transport-specific framing and connection shutdown stay with their engines.
#include <proxy/mitmproxy.hpp>
#include <proxy/mitmproxy_utils.hpp>
#include <staticcontent.hpp>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <ctime>

sx::mitmproxy::override_challenge_store& MitmProxy::override_challenges() {
    static sx::mitmproxy::override_challenge_store challenges(500);

    return challenges;
}

std::string MitmProxy::verify_flag_string(int code) {

    using verify_status_t = SSLCom::verify_status_t;

    switch(code) {
        case verify_status_t::VRF_OK:
            return "Certificate verification successful";
        case verify_status_t::VRF_SELF_SIGNED:
            return "Target certificate is self-signed";
        case verify_status_t::VRF_SELF_SIGNED_CHAIN:
            return "Server certificate's chain contains self-signed, untrusted CA certificate";
        case verify_status_t::VRF_UNKNOWN_ISSUER:
            return "Server certificate is issued by untrusted certificate authority";
        case verify_status_t::VRF_CLIENT_CERT_RQ:
            return "Server is asking client for a certificate";
        case verify_status_t::VRF_REVOKED:
            return "Server's certificate is REVOKED";
        case verify_status_t::VRF_HOSTNAME_FAILED:
            return "Client application asked for SNI server is not offering";
        case verify_status_t::VRF_INVALID:
            return "Certificate is not valid";
        case verify_status_t::VRF_ALLFAILED:
            return "It was not possible to obtain certificate status";
        case verify_status_t::VRF_CT_MISSING:
            return "Certificate Transparency info is missing";
        case verify_status_t::VRF_CT_FAILED:
            return "Certificate Transparency verification failed";
        default:
            return string_format("code 0x%04x", code);
    }
}

std::string MitmProxy::verify_flag_string_extended(int code) {

    using verify_status_t = SSLCom::vrf_other_values_t;

    switch(code) {
        case verify_status_t::VRF_OTHER_SHA1_SIGNATURE:
            return "Issuer certificate is signed using SHA1 (considered insecure).";
        case verify_status_t::VRF_OTHER_CT_INVALID:
            return "Certificate Transparency tag is INVALID.";
        case verify_status_t::VRF_OTHER_CT_FAILED:
            return "Unable to verify Certificate Transparency tag.";
        default:
            return string_format("extended code 0x%04x", code);
    }
}

std::string MitmProxy::replacement_ssl_verify_detail(SSLCom* scom) {

    using verify_status_t = SSLCom::verify_status_t;

    std::string reasons;

    if(!scom) return {};

    int reason_count = 1;
    auto add_reason = [&](std::string const& detail, bool critical = false) {
        reasons += html()->render_fields("tls_reason", {
            {"severity_class", critical ? " reason-critical" : ""},
            {"number", std::to_string(reason_count++)},
            {"text", sx::mitmproxy::html_escape(detail)}
        });
    };

    if(scom->verify_get() != verify_status_t::VRF_OK) {
        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED))
            add_reason(verify_flag_string(verify_status_t::VRF_SELF_SIGNED) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED_CHAIN))
            add_reason(verify_flag_string(verify_status_t::VRF_SELF_SIGNED_CHAIN) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_UNKNOWN_ISSUER))
            add_reason(verify_flag_string(verify_status_t::VRF_UNKNOWN_ISSUER) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_CLIENT_CERT_RQ))
            add_reason(verify_flag_string(verify_status_t::VRF_CLIENT_CERT_RQ) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_REVOKED))
            add_reason(verify_flag_string(verify_status_t::VRF_REVOKED) +
                       ". The certificate has been revoked. Do not continue.", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_CT_MISSING))
            add_reason(verify_flag_string(verify_status_t::VRF_CT_MISSING) +
                       ". For a public service, do not continue unless this is expected.", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_CT_FAILED))
            add_reason(verify_flag_string(verify_status_t::VRF_CT_FAILED) +
                       ". Do not continue unless you understand the risk.", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_INVALID))
            add_reason(verify_flag_string(verify_status_t::VRF_INVALID) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_HOSTNAME_FAILED))
            add_reason(verify_flag_string(verify_status_t::VRF_HOSTNAME_FAILED) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_ALLFAILED))
            add_reason(verify_flag_string(verify_status_t::VRF_ALLFAILED) + ".", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_EXTENDED_INFO)) {
            for(auto const& ei: scom->verify_extended_info()) {
                add_reason(verify_flag_string_extended(ei));
            }
        }
    }

    if(reason_count == 1) {
        add_reason(string_format("No detailed problem description is available (code 0x%x).",
                                 scom->verify_get()));
    }

    return reasons;
}


namespace {

// Render selected fields from the original server certificate, never the
// proxy-generated certificate. All peer-controlled text is escaped at the row.
std::string certificate_details(SSLCom* verification, std::string const& host) {
    std::string rows;

    auto row = [&](char const* label, std::string const& value) {
        rows += html()->render_fields("tls_certificate_field", {
            {"label", sx::mitmproxy::html_escape(label)},
            {"value", sx::mitmproxy::html_escape(value.empty() ? "Unavailable" : value)}
        });
    };

    auto printed = [](auto print) -> std::string {
        auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_mem()), BIO_free);

        if (!bio || print(bio.get()) <= 0) return {};

        char* data = nullptr;
        auto length = BIO_get_mem_data(bio.get(), &data);

        if (length <= 0) return {};

        constexpr long limit = 8192;
        auto text = std::string(data, static_cast<std::size_t>(std::min(length, limit)));

        if (length > limit) text += " [truncated]";

        return text;
    };

    row("Requested host", host);

    if (!verification) {
        row("Verification", "Verification details unavailable.");

        return rows;
    }

    row("Recorded verification flags", string_format("0x%04x", verification->verify_get()));
    row("Revocation information source",
        verification->verify_origin() == SSLCom::verify_origin_t::NONE ? "Not recorded." :
        SSLCom::verify_origin_str(verification->verify_origin()));

    auto* certificate = verification->target_cert();

    if (!certificate) {
        row("Original server certificate", "Certificate unavailable; no certificate fields can be shown.");

        return rows;
    }

    row("Subject", printed([&](BIO* bio) {
        return X509_NAME_print_ex(bio, X509_get_subject_name(certificate), 0, XN_FLAG_RFC2253);
    }));
    row("Issuer", printed([&](BIO* bio) {
        return X509_NAME_print_ex(bio, X509_get_issuer_name(certificate), 0, XN_FLAG_RFC2253);
    }));
    row("Serial number", printed([&](BIO* bio) {
        return i2a_ASN1_INTEGER(bio, X509_get_serialNumber(certificate));
    }));
    row("Valid from (UTC)", printed([&](BIO* bio) {
        return ASN1_TIME_print(bio, X509_get0_notBefore(certificate));
    }));
    row("Valid until (UTC)", printed([&](BIO* bio) {
        return ASN1_TIME_print(bio, X509_get0_notAfter(certificate));
    }));

    // This is a display-time observation, not a replacement for the recorded
    // validation verdict (which also covers trust, revocation and TLS policy).
    int const starts = X509_cmp_current_time(X509_get0_notBefore(certificate));
    int const ends = X509_cmp_current_time(X509_get0_notAfter(certificate));

    const char* validity = "Within the certificate validity period.";

    if (starts == 0 || ends == 0) {
        validity = "Cannot parse certificate validity.";
    } else if (starts > 0) {
        validity = "Not yet valid.";
    } else if (ends < 0) {
        validity = "Expired.";
    }

    row("Validity at page generation", validity);

    int const san_index = X509_get_ext_by_NID(certificate, NID_subject_alt_name, -1);

    row("Subject alternative names", san_index < 0 ? "Not present." : printed([&](BIO* bio) {
        return X509V3_EXT_print(bio, X509_get_ext(certificate, san_index), 0, 0);
    }));

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    std::string fingerprint;

    if (X509_digest(certificate, EVP_sha256(), digest, &size) == 1) {
        for (unsigned int i = 0; i < size; ++i) {
            if (i) fingerprint += ':';
            fingerprint += string_format("%02X", static_cast<unsigned>(digest[i]));
        }
    }

    row("SHA-256 fingerprint", fingerprint);

    return rows;
}

} // namespace

std::string MitmProxy::replacement_ssl_page(SSLCom* scom, sx::engine::http::app_HttpRequest const* app_request, std::string const& more_info) {
    if(!app_request) return {};

    auto const reasons = replacement_ssl_verify_detail(scom);
    auto const details = html()->render_fields("tls_certificate_details", {
        {"reasons", reasons},
        {"fields", certificate_details(scom, app_request->http_data.host)}
    });

    return html()->render_tls_replacement(
        sx::mitmproxy::html_escape(app_request->http_data.proto + app_request->http_data.host),
        reasons, more_info, details);
}

bool MitmProxy::tls_override_active(std::string const& scope, SSLComOptionsCert const& options) {
    if (scope.empty()) return false;

    auto lock = std::scoped_lock(whitelist_verify().getlock());
    auto entry = whitelist_verify().get(scope);

    if (!entry) return false;

    if (entry->value().single_use) {
        whitelist_verify().erase(scope);
    } else if (options.failed_check_override_timeout_type == 1) {
        auto ttl = sx::mitmproxy::override_ttl_seconds(options.failed_check_override_timeout);

        if (!ttl) {
            whitelist_verify().erase(scope);

            return false;
        }

        entry->expired_at() = std::time(nullptr) + *ttl;
    }

    return true;
}

MitmProxy::TlsReplacement MitmProxy::build_tls_replacement(
    SSLCom* verification, sx::engine::http::app_HttpRequest const* request,
    std::string const& scope) {
    using namespace sx::mitmproxy;

    TlsReplacement result;

    auto error = [&](char const* message, char const* reason) {
        result.body = html()->render_fields("tls_replacement_error", {{"message", html_escape(message)}});
        result.reason = reason;

        return result;
    };

    if (!verification) {
        result.status = 500;

        return error("Certificate verification details unavailable.", "verification unavailable");
    }

    if (!request) {
        result.body = html()->render_fields("tls_redirect_top", {{"target", "/"}});
        result.reason = "enforced";

        return result;
    }

    auto const& data = request->http_data;
    auto original = [&]() {
        auto encoded = query_parameter(data.params, "orig_url");

        return encoded ? decode_relative_target(*encoded).value_or("/") : std::string("/");
    };

    const auto route = classify_replacement_route(data.uri);
    auto const& options = verification->opt.cert;

    if (route == replacement_route::override_action) {
        if (!options.failed_check_override) return error("Action is denied.", "override disabled");

        if (scope.empty() || !override_challenges().consume(
                scope, override_token_from_route(data.uri), std::time(nullptr))) {
            return error("Action is invalid or expired.", "invalid override challenge");
        }

        auto ttl = override_ttl_seconds(options.failed_check_override_timeout);

        if (!ttl) return error("Override timeout is invalid.", "invalid override timeout");

        {
            auto lock = std::scoped_lock(whitelist_verify().getlock());

            whitelist_verify().set(scope, new whitelist_verify_entry_t({}, *ttl));
        }

        auto target = html_escape(original());

        result.body = html()->render_fields("tls_redirect", {{"target", target}});
        result.status = 200;
        result.override_applied = true;
        result.reason = "override";

        return result;
    }

    if (route == replacement_route::warning) {
        std::string form;

        if (options.failed_check_override && !scope.empty() &&
            override_ttl_seconds(options.failed_check_override_timeout)) {
            std::array<unsigned char, 16> bytes {};

            if (RAND_bytes(bytes.data(), bytes.size()) == 1) {
                static constexpr char hex[] = "0123456789abcdef";
                std::string token;

                for (auto byte : bytes) {
                    token += hex[byte >> 4];
                    token += hex[byte & 15];
                }

                form = html()->render_tls_override_form(html_escape(token), html_escape(original()));

                if (!form.empty()) {
                    override_challenges().issue(scope, token, std::time(nullptr), 120);
                }
            }
        }

        result.body = replacement_ssl_page(verification, request, form);
        result.reason = "warning";
    } else if (data.uri == "/") {
        result.body = html()->render_fields("tls_redirect", {
            {"target", "/SM/IT/HP/RO/XY/warning?q=1"}
        });
        result.reason = "redirect";
    } else {
        auto target = data.uri;

        if (!data.params.empty()) target += "?" + data.params;

        // Only the fixed local route and a percent-encoded query enter the
        // JavaScript string context; never interpolate a raw request target.
        result.body = html()->render_fields("tls_redirect_top", {
            {"target", "/SM/IT/HP/RO/XY/warning?q=1&orig_url=" + query_encode(target)}
        });
        result.reason = "redirect";
    }

    return result;
}
