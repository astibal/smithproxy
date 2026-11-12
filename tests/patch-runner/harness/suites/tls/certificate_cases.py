"""Certificate policy cases shared by TCP/TLS and QUIC integration suites."""

CERTIFICATE_PROFILES = {
    "self_signed_reject": {},
    "self_signed_allow": {"allow_self_signed": True},
    "expired_reject": {},
    "expired_allow": {"allow_invalid_certs": True},
    "future_reject": {},
    "future_allow": {"allow_invalid_certs": True},
    "untrusted_reject": {},
    "untrusted_allow": {"allow_untrusted_issuers": True},
    "require_staple": {"ocsp_stapling": True, "ocsp_stapling_mode": 2},
    "require_ct": {"ct_enable": True},
    "configured_identity_only": {"only_custom_certs": True,
                                 "sni_based_cert": False, "ip_based_cert": False},
}


def identity(name):
    return next((kind for kind in ("self_signed", "expired", "future", "untrusted")
                 if name.startswith(kind)), "origin")


def rejects(name):
    return name.endswith("_reject") or name in (
        "require_staple", "require_ct", "configured_identity_only")


if __name__ == "__main__":
    print("quic-cert.baseline")
    for name in CERTIFICATE_PROFILES:
        print("quic-cert." + name)
