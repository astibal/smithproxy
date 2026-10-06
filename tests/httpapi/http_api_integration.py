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
import threading
import time


TLS_HELPERS = pathlib.Path(__file__).resolve().parents[1] / "tls"
sys.path.insert(0, str(TLS_HELPERS))
from starttls_socks_integration import Address, free_port, make_config, socks_connect


class HoldingTlsOrigin:
    def __init__(self, certificate, key):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.certificate = certificate
        self.key = key
        self.release = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certificate, self.key)
            raw, _ = self.listener.accept()
            with raw, context.wrap_socket(raw, server_side=True) as tls:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = tls.recv(4096)
                    if not chunk:
                        raise RuntimeError("TLS request closed before headers")
                    request.extend(chunk)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"
                            b"Connection: keep-alive\r\n\r\nAPI-TLS")
                self.release.wait(timeout=15)
        except Exception as exception:
            self.error = exception

    def close(self):
        self.release.set()
        self.listener.close()
        self.thread.join(timeout=5)


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
        text = text.replace(
            "settings = {",
            "settings = {\n"
            "    webhook = { enabled = true; url = \"https://configured.invalid/\"; "
            "tls_verify = false; api_override = true; };",
            1,
        )
        for name in ("allow_untrusted_issuers", "allow_invalid_certs",
                     "allow_self_signed"):
            text = text.replace(f"{name} = FALSE;", f"{name} = TRUE;", 1)
        config.write_text(text)

        origin = socket.socket()
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(5)
        origin_port = origin.getsockname()[1]

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
        proxied = None
        origin_peer = None
        tls_origin = HoldingTlsOrigin(source / "etc/certs/default/srv-cert.pem",
                                      source / "etc/certs/default/srv-key.pem")
        tls_client = None
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
            cookie_values = [value for name, value in headers if name.lower() == "set-cookie"]
            assert len(cookie_values) == 2
            auth_cookie = next(value for value in cookie_values
                               if value.startswith("__sx_api="))
            csrf_cookie = next(value for value in cookie_values
                               if value.startswith("__Host-csrf_token="))
            assert "Max-Age=60" in auth_cookie and "Max-Age:" not in auth_cookie
            assert all(flag in auth_cookie
                       for flag in ("Secure", "HttpOnly", "Path=/", "SameSite=Strict"))
            assert "Max-Age=60" in csrf_cookie
            assert all(flag in csrf_cookie
                       for flag in ("Secure", "Path=/", "SameSite=Strict"))
            auth_headers = {
                "Content-Type": "application/json",
                "Cookie": "; ".join(value.split(";", 1)[0] for value in cookie_values),
                "csrf_token": authorization["csrf_token"],
            }

            status, _, payload = api_request(api_port, "GET", "/cacert")
            assert status == 200 and b"BEGIN CERTIFICATE" in payload

            status, _, payload = api_request(
                api_port, "GET", "/api/diag/ssl/cache/stats",
                headers={"X-API-Key": api_key})
            assert status == 200
            assert isinstance(json.loads(payload), dict)

            status, _, payload = api_request(
                api_port, "GET", "/api/diag/ssl/cache/print?verbosity=6",
                headers={"X-API-Key": api_key})
            assert status == 200
            assert isinstance(json.loads(payload), list)

            for headers in ({}, {"X-API-Key": "wrong"}):
                status, _, payload = api_request(
                    api_port, "GET", "/api/diag/ssl/cache/stats", headers=headers)
                assert status == 401, (status, payload)
                assert json.loads(payload) == {"error": "access denied"}

            status, _, payload = api_request(
                api_port, "POST", "/api/diag/proxy/neighbor/update",
                body="", headers={"X-API-Key": api_key})
            assert status == 401, (status, payload)
            assert json.loads(payload) == {"error": "access denied"}

            # Keep a real flow alive while serializing the session API.  The
            # empty-list case cannot exercise host/proxy JSON fields.
            proxied = socks_connect(
                socks_port, origin_port,
                Address(socket.AF_INET, "127.0.0.1", "127.0.0.1", 1))
            proxied.sendall(b"http-api active session\n")
            origin_peer, _ = origin.accept()
            assert origin_peer.recv(4096) == b"http-api active session\n"

            status, _, payload = api_request(
                api_port, "GET", "/api/diag/proxy/session/list",
                headers={"X-API-Key": api_key})
            assert status == 200
            sessions = json.loads(payload)
            assert isinstance(sessions, list) and sessions, sessions
            assert any("oid" in session and "left" in session and "right" in session
                       for session in sessions), sessions

            tls_origin.start()
            tls_raw = socks_connect(
                socks_port, tls_origin.port,
                Address(socket.AF_INET, "127.0.0.1", "127.0.0.1", 1))
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE
            tls_client = tls_context.wrap_socket(
                tls_raw, server_hostname="api.integration.invalid")
            tls_client.sendall(
                b"GET /api-tls HTTP/1.1\r\nHost: api.integration.invalid\r\n\r\n")
            response = bytearray()
            while b"API-TLS" not in response:
                response.extend(tls_client.recv(4096))

            status, _, payload = api_request(
                api_port, "POST", "/api/diag/proxy/session/list",
                body=json.dumps({"params": {
                    "active": False, "tlsinfo": True, "verbose": True}}),
                headers=auth_headers)
            assert status == 200
            verbose_sessions = json.loads(payload)
            assert verbose_sessions, verbose_sessions
            tls_entries = [session["tlsinfo"] for session in verbose_sessions
                           if "tlsinfo" in session]
            assert tls_entries, verbose_sessions
            assert all(set(entry) == {"left", "right"} for entry in tls_entries), tls_entries

            status, _, payload = api_request(
                api_port, "POST", "/api/diag/proxy/session/list",
                body=json.dumps({"params": {"active": True}}), headers=auth_headers)
            assert status == 200 and isinstance(json.loads(payload), list)

            for path in ("/api/diag/proxy/neighbor/list",
                         "/api/diag/proxy/neighbor/list?raw=1"):
                status, _, payload = api_request(
                    api_port, "GET", path, headers={"X-API-Key": api_key})
                assert status == 200
                assert isinstance(json.loads(payload), list)

            status, _, payload = api_request(
                api_port, "POST", "/api/diag/proxy/neighbor/update",
                body=json.dumps({"params": {"hostname_tags": "invalid"}}),
                headers=auth_headers)
            assert status == 200
            assert json.loads(payload) == {"updated_entries": 0}

            def config_request(path, params):
                status, _, payload = api_request(
                    api_port, "POST", path,
                    body=json.dumps({"params": params}), headers=auth_headers)
                assert status == 200, (status, payload)
                return json.loads(payload)

            config = config_request(
                "/api/config/uni/get",
                {"section": "settings", "name": "http_api"})
            assert config["success"]["settings.http_api"]["key_timeout"] == "60", config

            result = config_request(
                "/api/config/uni/get",
                {"section": "does_not_exist", "name": "entry"})
            assert "error" in result, result

            result = config_request(
                "/api/config/uni/set",
                {"section": "settings.http_api", "name": "key_timeout",
                 "changeset": {"value": "60"}})
            assert result == {"error": "configuration target must be a group"}, result

            temporary_port = "api_coverage_temp"
            result = config_request(
                "/api/config/uni/add",
                {"section": "port_objects", "name": temporary_port})
            assert "success" in result, result
            result = config_request(
                "/api/config/uni/add",
                {"section": "port_objects", "name": temporary_port})
            assert "error" in result, result

            config = config_request(
                "/api/config/uni/get",
                {"section": "port_objects", "name": temporary_port})
            port_path = f"port_objects.{temporary_port}"
            assert config["success"][port_path] == {"start": "0", "end": "65535"}, config

            for invalid_changeset in (None, "not-an-object", [], {"key_timeout": 61}):
                params = {"section": "port_objects", "name": temporary_port}
                if invalid_changeset is not None:
                    params["changeset"] = invalid_changeset
                result = config_request("/api/config/uni/set", params)
                assert "error" in result, result

            result = config_request(
                "/api/config/uni/set",
                {"section": "port_objects", "name": temporary_port,
                 "changeset": {"start": "1234", "zz_missing": "x"}})
            assert "error" in result, result
            config = config_request(
                "/api/config/uni/get",
                {"section": "port_objects", "name": temporary_port})
            assert config["success"][port_path]["start"] == "0", config

            result = config_request(
                "/api/config/uni/set",
                {"section": "port_objects", "name": temporary_port,
                 "changeset": {"start": "1234", "end": "1234"}})
            assert "success" in result, result
            config = config_request(
                "/api/config/uni/get",
                {"section": "port_objects", "name": temporary_port})
            assert config["success"][port_path] == {"start": "1234", "end": "1234"}, config

            status, _, payload = api_request(
                api_port, "POST", "/api/do/ssl/custom/reload", body="{}",
                headers=auth_headers)
            assert status == 200, (status, payload)
            reload_result = json.loads(payload)
            assert set(reload_result) == {"result", "count"}, reload_result

            status, _, payload = api_request(
                api_port, "POST", "/api/webhook/register",
                body=json.dumps({"params": {"rande_url": ""}}),
                headers=auth_headers)
            document = json.loads(payload)
            assert status == 200 and document.get("status") == "rejected", (status, document)

            status, _, payload = api_request(
                api_port, "POST", "/api/webhook/register",
                body=json.dumps({"params": {
                    "rande_url": "https://override.invalid/",
                    "rande_tls_verify": True,
                }}),
                headers=auth_headers)
            document = json.loads(payload)
            assert status == 200 and document.get("status") == "accepted", (status, document)

            status, _, payload = api_request(
                api_port, "POST", "/api/webhook/unregister", body="{}",
                headers=auth_headers)
            document = json.loads(payload)
            assert status == 200 and document.get("status") == "unregistered", (status, document)

            status, _, payload = api_request(
                api_port, "POST", "/api/status/ping", body="{}",
                headers={"Content-Type": "application/json"})
            assert status == 200 and json.loads(payload)["status"] == "ok"

            status, _, payload = api_request(
                api_port, "POST", "/api/status/ping", body="",
                headers={"Content-Type": "application/json"})
            assert status == 200 and json.loads(payload)["status"] == "ok"

            status, _, payload = api_request(
                api_port, "POST", "/api/status/ping", body="not-json",
                headers={"Content-Type": "application/json"})
            assert status == 200
            assert json.loads(payload)["error"] == "unknown parameters"

            status, _, payload = api_request(api_port, "GET", "/api/authorize?key=wrong")
            assert status == 403, (status, payload)
            assert json.loads(payload) == {"error": "access denied"}

            for body in ("", "not-json", json.dumps({"access_key": "wrong"})):
                status, _, payload = api_request(
                    api_port, "POST", "/api/authorize", body=body,
                    headers={"Content-Type": "application/json"})
                assert status == 401, (status, payload)
                assert json.loads(payload) == {"error": "access denied"}

            status, _, payload = api_request(
                api_port, "POST", "/api/login", body="username=missing-password",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert status == 401, (status, payload)
            assert json.loads(payload) == {"error": "access denied"}
            print("HTTP API control plane: PASS")
        finally:
            if proxied is not None:
                proxied.close()
            if origin_peer is not None:
                origin_peer.close()
            if tls_client is not None:
                tls_client.close()
            tls_origin.close()
            origin.close()
            process.terminate()
            try:
                output, _ = process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            if sys.exc_info()[0] is not None:
                if tls_origin.error is not None:
                    print(f"TLS origin error: {tls_origin.error!r}", file=sys.stderr)
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
