#!/usr/bin/env python3
"""Measure TLS profile promises on both real handshake legs.

Each profile/version gets a separate destination port and origin SSLContext.
This keeps tickets and the proxy's upstream cache independent between cases.
The origin returns its own negotiated state in the application response; no
proxy log or configuration value is used as evidence of enforcement.
"""

import argparse
import json
import re
import socket
import ssl
import subprocess
import threading
from pathlib import Path


try:
    from .certificate_cases import CERTIFICATE_PROFILES, rejects
except ImportError:
    from certificate_cases import CERTIFICATE_PROFILES, rejects


PROFILES = {
    "baseline": {},
    "no_left_reuse": {"left_disable_reuse": True},
    "no_right_reuse": {"right_disable_reuse": True},
    "no_reuse": {"left_disable_reuse": True, "right_disable_reuse": True},
    "no_left_pfs": {"left_use_pfs": False},
    "no_right_pfs": {"right_use_pfs": False},
    "no_pfs": {"use_pfs": False},
    "no_alpn": {"alpn_block": True},
    "bypass": {"inspect": False},
    **CERTIFICATE_PROFILES,
}
VERSIONS = (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)


def cases():
    for index, (name, options) in enumerate(PROFILES.items()):
        for version_index, version in enumerate(VERSIONS):
            yield name, options, version, 21400 + index * 2 + version_index


def configure(text):
    """Install explicit per-port policies before the sample catch-all rules."""
    profiles, ports, rules = [], [], []
    for name, options in PROFILES.items():
        fields = {
            "inspect": True, "ct_enable": False, "ocsp_stapling": False,
            "failed_certcheck_replacement": False, **options,
        }
        settings = " ".join(f"{key} = {str(value).lower()};" for key, value in fields.items())
        profiles.append(f"profile_{name} = {{ {settings} }};")

    for name, _, _, port in cases():
        ports.append(f"profile_{port} = {{ start={port}; end={port}; }};")
        rules.append(
            f'{{ name="profile-{port}"; proto="tcp"; src=["any", "any6"]; '
            f'sport=["all"]; dst=["any", "any6"]; dport=["profile_{port}"]; '
            f'tls_profile="profile_{name}"; detection_profile="detect"; '
            'action="accept"; nat="auto"; routing="none"; },'
        )

    for section, opening, additions in (
        ("tls_profiles", "{", profiles), ("port_objects", "{", ports),
        ("policy", "(", rules),
    ):
        pattern = rf"({section}\s*=\s*{re.escape(opening)})"
        text, count = re.subn(pattern, lambda match: match[1] + "\n" + "\n".join(additions),
                              text, count=1)
        if count != 1:
            raise ValueError(f"cannot install TLS matrix in {section}")
    return text


def state(connection):
    return {"version": connection.version(), "cipher": connection.cipher()[0],
            "alpn": connection.selected_alpn_protocol(), "reused": connection.session_reused}


def serve(listener, context):
    while True:
        raw, _ = listener.accept()
        raw.settimeout(5)
        try:
            with context.wrap_socket(raw, server_side=True) as connection:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        break
                    request.extend(part)

                if not request:
                    continue

                body = json.dumps(state(connection)).encode()
                connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                                   + str(len(body)).encode() + b"\r\n\r\n" + body)
                connection.unwrap().close()
        except (OSError, ssl.SSLError):
            # Negative protocol cases deliberately fail the origin handshake.
            raw.close()


def start_origins(certificates):
    for host in ("198.18.20.2", "fd00:20::2"):
        for name, _, version, port in cases():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = version
            identity = next((kind for kind in ("self_signed", "expired", "future", "untrusted")
                             if name.startswith(kind)), "origin")
            context.load_cert_chain(certificates / f"{identity}-cert.pem", certificates / f"{identity}-key.pem")
            context.set_alpn_protocols(["http/1.1"])
            # Include RSA key exchange as the positive control for no-PFS.
            context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256")
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            listener = socket.create_server((host, port), family=family)
            threading.Thread(target=serve, args=(listener, context), daemon=True).start()


def prepare_certificates(certificates):
    """Disposable negative identities; never alter the system trust store."""
    def openssl(*args):
        # x509 also limits its derived CA serial path; cwd alone does not help
        # while absolute certificate filenames are still passed on the command.
        arguments = [str(arg.relative_to(certificates)) if isinstance(arg, Path) else str(arg)
                     for arg in args]
        result = subprocess.run(["openssl", *arguments], cwd=certificates,
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"openssl {args[0]} failed: {result.stderr.strip()}")

    for name in ("self_signed", "expired", "future", "untrusted"):
        key = certificates / f"{name}-key.pem"
        request = certificates / f"{name}.csr"
        cert = certificates / f"{name}-cert.pem"
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=origin.runner.lab",
                "-keyout", key, "-out", request)
        key.chmod(0o600)
        if name == "self_signed":
            openssl("x509", "-req", "-in", request, "-signkey", key, "-days", "2",
                    "-extfile", certificates / "origin.ext", "-out", cert)
        elif name in ("expired", "future"):
            # `openssl ca` supports fixed validity dates on older releases too.
            (certificates / f"{name}-index").write_text("")
            (certificates / f"{name}-serial").write_text("1000\n")
            config = certificates / f"{name}-ca.cnf"
            config.write_text(
                "[ca]\ndefault_ca=issuer\n[issuer]\n"
                # openssl ca has a short internal output filename buffer.
                # Relative paths also work in deeply nested runner workspaces.
                f"database={name}-index\nserial={name}-serial\nnew_certs_dir=.\n"
                "certificate=origin-ca.pem\nprivate_key=origin-ca-key.pem\n"
                "default_md=sha256\npolicy=names\n[names]\ncommonName=supplied\n"
            )
            openssl("ca", "-batch", "-notext", "-config", config, "-in", request,
                    "-startdate", "20200101000000Z" if name == "expired" else "20990101000000Z",
                    "-enddate", "20200102000000Z" if name == "expired" else "20990102000000Z",
                    "-extfile", certificates / "origin.ext", "-out", cert)
        else:
            # The proxy CA is deliberately absent from the upstream CA bundle.
            openssl("x509", "-req", "-in", request, "-CA", certificates / "ca-cert.pem",
                    "-CAkey", certificates / "ca-key.pem", "-CAcreateserial",
                    "-days", "2",
                    "-extfile", certificates / "origin.ext", "-out", cert)


def probe(host, port, version, ca_file, bypass=False, certificate_exception=False, seed_port=None):
    if bypass:
        ca_file = str(Path(ca_file).with_name("origin-ca.pem"))
    context = ssl.create_default_context(cafile=ca_file)
    if certificate_exception:
        # Smithproxy preserves the failed upstream trust verdict in its forged
        # identity. Test proxy admission separately from the client's decision.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = context.maximum_version = version
    context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256")
    context.set_alpn_protocols(["http/1.1"])
    session, observations = None, []

    for attempt in range(3):
        try:
            destination = seed_port if attempt == 0 and seed_port is not None else port
            with socket.create_connection((host, destination), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="origin.runner.lab", session=session) as tls:
                    left = state(tls)
                    tls.sendall(b"GET /profile HTTP/1.1\r\nHost: origin.runner.lab\r\nConnection: close\r\n\r\n")
                    response = bytearray()
                    while chunk := tls.recv(4096):
                        response.extend(chunk)

                    header, body = bytes(response).split(b"\r\n\r\n", 1)
                    if not header.startswith(b"HTTP/1.1 200"):
                        raise ValueError(f"unexpected response: {header!r}")
                    observations.append({"left": left, "right": json.loads(body)})
                    session = tls.session
                    tls.unwrap().close()
        except (OSError, ValueError) as error:
            observations.append({"error": type(error).__name__, "detail": str(error)})
            break
    return observations


def check(name, options, version, observations):
    errors = []
    no_pfs = any(options.get(key) is False for key in ("use_pfs", "left_use_pfs", "right_use_pfs"))
    reject = rejects(name)
    if reject or (no_pfs and version == ssl.TLSVersion.TLSv1_3):
        # Fresh TLS 1.3 requires (EC)DHE. A TLS-1.3-only peer cannot comply.
        if len(observations) != 1 or observations[0].get("error") not in ("SSLError", "SSLEOFError", "ConnectionResetError"):
            errors.append("forbidden handshake was not promptly rejected")
        return errors

    if len(observations) != 3 or any("error" in item for item in observations):
        return ["three successful application exchanges required"]

    for side in ("left", "right"):
        # Accepted certificate exceptions are intentionally not trusted for
        # upstream cache reuse. Downstream tickets remain independently valid.
        no_reuse = options.get(f"{side}_disable_reuse") or (side == "right" and name.endswith("_allow"))
        expected = [False, False, False] if no_reuse else [False, True, True]
        actual = [item[side]["reused"] for item in observations]
        if actual != expected:
            errors.append(f"{side} reuse: expected {expected}, got {actual}")

        if options.get(f"{side}_use_pfs", options.get("use_pfs", True)) is False:
            if any(item[side]["cipher"] != "AES128-GCM-SHA256" for item in observations):
                errors.append(f"{side} no-PFS did not negotiate RSA key exchange")

        expected_alpn = None if options.get("alpn_block") else "http/1.1"
        if any(item[side]["alpn"] != expected_alpn for item in observations):
            errors.append(f"{side} ALPN: expected {expected_alpn!r}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    for name, options, version, port in cases():
        observations = probe(args.host, port, version, args.ca_file, name == "bypass",
                             name.endswith(("_allow", "_reject")))
        errors = check(name, options, version, observations)
        results.append({"profile": name, "version": version.name, "observations": observations, "failures": errors})
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(f"{'FAIL' if errors else 'PASS'} {name} {version.name}: {'; '.join(errors)}", flush=True)

    # Issuing no new tickets is not enough: a restrictive profile must also
    # reject a ticket previously obtained from a permissive policy for this SNI.
    for name, _, version, port in cases():
        if name not in ("no_left_reuse", "no_reuse"):
            continue
        seed_port = 21400 + VERSIONS.index(version)
        observations = probe(args.host, port, version, args.ca_file, seed_port=seed_port)
        actual = [item.get("left", {}).get("reused") for item in observations]
        errors = [] if actual == [False, False, False] else [f"old ticket accepted or exchange failed: {actual}"]
        label = name + "_old_ticket"
        results.append({"profile": label, "version": version.name,
                        "observations": observations, "failures": errors})
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(f"{'FAIL' if errors else 'PASS'} {label} {version.name}: {'; '.join(errors)}", flush=True)
    return int(any(result["failures"] for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
