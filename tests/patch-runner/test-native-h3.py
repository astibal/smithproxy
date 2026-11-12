#!/usr/bin/env python3
"""Exercise real native endpoints: payload, stream completion and TLS identity."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def certificate(directory, name, openssl):
    """Create a separate local test identity, never using a host trust-store key."""
    cert, key = directory / f"{name}.pem", directory / f"{name}.key"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "2",
                    "-subj", "/CN=origin.runner.lab", "-addext",
                    "subjectAltName=DNS:origin.runner.lab"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    key.chmod(0o600)
    return cert, key


def main():
    """Fail unless both endpoint binaries enforce the benchmark's contracts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    with tempfile.TemporaryDirectory(prefix="native-h3-contract-") as temporary:
        root = Path(temporary)
        cert, key = certificate(root, "origin", args.openssl)
        unrelated_ca, _ = certificate(root, "unrelated", args.openssl)
        size = 1024 * 1024
        www = root / "www/bulk"
        www.mkdir(parents=True)
        payload = www / str(size)
        with payload.open("wb") as output:
            output.truncate(size)
        bad = root / "bad.bin"
        bad.write_bytes(bytes(size - 1) + b"x")
        short = root / "short.bin"
        short.write_bytes(bytes(size - 1))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with (root / "server.log").open("w+") as log:
            server = subprocess.Popen([str(runtime / "bin/h3-server"), "-q", "-d", str(www.parent),
                                       "*", str(port), str(key), str(cert)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while True:
                    sockets = subprocess.check_output(["ss", "-H", "-lunp", f"sport = :{port}"], text=True)
                    if f"pid={server.pid}," in sockets:
                        break
                    if server.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError("native server did not become ready")
                    time.sleep(.05)

                def request(host, *, body=None, ca=cert, hostname="origin.runner.lab"):
                    """Return completion records, requiring the native client to exit promptly."""
                    argv = [str(runtime / "bin/h3-client"), "-q", "--exit-on-all-streams-close",
                            "--handshake-timeout=2s", "--timeout=2s", f"--sni={hostname}"]
                    if body is not None:
                        argv += ["--http-method=POST", "-d", str(body)]
                    argv += [host, str(port), f"https://{hostname}:{port}/bulk/{size}"]
                    result = subprocess.run(argv, env=dict(os.environ, SSL_CERT_FILE=str(ca)),
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
                    records = [json.loads(line) for line in result.stdout.splitlines()
                               if line.startswith('{"h3_benchmark":')]
                    return records, result

                for host in ("127.0.0.1", "::1"):
                    for body in (None, payload):
                        records, result = request(host, body=body)
                        assert result.returncode == 0 and len(records) == 1, result
                        measured = records[0]
                        assert measured["http_code"] == 200 and measured["error_code"] in (0, 256), measured
                        assert not measured["nonzero"], measured
                        amount = measured["size_upload" if body else "size_download"]
                        assert amount == size, measured
                    for body in (bad, short):
                        records, result = request(host, body=body)
                        assert len(records) == 1 and records[0]["http_code"] == 400, result
                    for options in ({"ca": unrelated_ca}, {"hostname": "wrong.runner.lab"}):
                        records, result = request(host, **options)
                        assert not records, ("untrusted identity was accepted", records, result)
                print("PASS native H3: IPv4/IPv6 download, upload, corrupt/short body, wrong CA and hostname")
            finally:
                if server.poll() is None:
                    server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
