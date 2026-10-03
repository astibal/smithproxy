#!/usr/bin/env python3

"""Exercise the built-in HTTPS control plane against a real Smithproxy process."""

import argparse
import http.client
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time


TLS_HELPERS = pathlib.Path(__file__).resolve().parents[1] / "tls"
sys.path.insert(0, str(TLS_HELPERS))
from starttls_socks_integration import free_port, make_config


def api_request(port, method, path, body=None, headers=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        "127.0.0.1", port, timeout=5, context=context)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        connection.close()


def wait_for_api(process, port, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            raise RuntimeError(
                f"smithproxy exited before HTTP API startup ({process.returncode}):\n{output}")
        try:
            status, _, payload = api_request(port, "GET", "/api/status/ping")
            if status == 200 and json.loads(payload)["status"] == "ok":
                return
        except (OSError, ssl.SSLError, json.JSONDecodeError, KeyError):
            pass
        time.sleep(0.05)
    raise RuntimeError("HTTP API listener did not become ready")


def run(args):
    executable = args.smithproxy.resolve()
    source = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-http-api-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        socks_port = free_port()
        cli_port = free_port()
        api_port = free_port()
        make_config(source / "etc/smithproxy.cfg", config, source, runtime,
                    socks_port, cli_port)

        api_key = "smithproxy-integration-api-key"
        api_settings = f'''accept_api = TRUE;
    http_api = {{
        keys = [ "{api_key}" ];
        key_timeout = 60;
        key_extend_on_access = TRUE;
        loopback_only = TRUE;
        allow_api_header = TRUE;
        port = {api_port};
        pam_login = FALSE;
    }};'''
        text = config.read_text()
        if "accept_api = FALSE;" not in text:
            raise RuntimeError("generated fixture does not disable accept_api")
        text = text.replace("accept_api = FALSE;", api_settings, 1)
        # This scenario isolates the control plane; SOCKS transport coverage
        # belongs to its own tests and would unnecessarily reserve TCP+UDP.
        text = text.replace("accept_socks = TRUE;", "accept_socks = FALSE;", 1)
        config.write_text(text)

        process = subprocess.Popen(
            [str(executable), "--config-file", str(config), "--diagnose"],
            cwd=source,
            env={**os.environ,
                 "SMITHPROXY_PID_FILE": str(runtime / "smithproxy.pid")},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = ""
        try:
            wait_for_api(process, api_port)

            status, _, payload = api_request(api_port, "GET", "/api/status/ping")
            assert status == 200
            status_document = json.loads(payload)
            assert status_document["status"] == "ok"
            assert "version" in status_document and "uptime" in status_document

            status, headers, payload = api_request(
                api_port, "GET", f"/api/authorize?key={api_key}")
            assert status == 200
            authorization = json.loads(payload)
            assert authorization["auth_token"] and authorization["csrf_token"]
            assert len([value for name, value in headers if name.lower() == "set-cookie"]) == 2

            status, _, payload = api_request(api_port, "GET", "/cacert")
            assert status == 200 and b"BEGIN CERTIFICATE" in payload

            status, _, payload = api_request(
                api_port, "GET", "/api/diag/ssl/cache/stats",
                headers={"X-API-Key": api_key})
            assert status == 200
            assert isinstance(json.loads(payload), dict)

            status, _, payload = api_request(
                api_port, "POST", "/api/status/ping", body="{}",
                headers={"Content-Type": "application/json"})
            assert status == 200 and json.loads(payload)["status"] == "ok"

            status, _, payload = api_request(
                api_port, "POST", "/api/status/ping", body="not-json",
                headers={"Content-Type": "application/json"})
            assert status == 200
            assert json.loads(payload)["error"] == "unknown parameters"

            status, _, payload = api_request(api_port, "GET", "/api/authorize?key=wrong")
            assert status == 403, (status, payload)
            print("HTTP API control plane: PASS")
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            if sys.exc_info()[0] is not None:
                print("--- smithproxy stdout ---", file=sys.stderr)
                print(output, file=sys.stderr)
                for log in sorted(runtime.glob("*.log")):
                    print(f"--- {log.name} ---", file=sys.stderr)
                    print(log.read_text(errors="replace"), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, default=pathlib.Path.cwd())
    run(parser.parse_args())


if __name__ == "__main__":
    main()
