#!/usr/bin/env python3

"""Exercise the built-in HTTPS control plane against a real Smithproxy process."""

import argparse
import http.client
import json
import os
import pathlib
import re
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

CLI_HELPERS = pathlib.Path(__file__).resolve().parents[1] / "cli"
sys.path.insert(0, str(CLI_HELPERS))
from libcli2_process_e2e import Cli, wait_for_port


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
        if self.thread.ident is not None:
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
        administrator_api_key = "smithproxy-integration-administrator-key"
        administrator_key_file = runtime / "administrator-api.key"
        administrator_key_file.write_text(administrator_api_key)
        administrator_key_file.chmod(0o600)
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
                 "SMITHPROXY_PID_FILE": str(runtime / "smithproxy.pid"),
                 "SMITHPROXY_ADMIN_API_KEY_FILE": str(administrator_key_file)},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = ""
        proxied = None
        origin_peer = None
        cli = None
        tls_origin = HoldingTlsOrigin(source / "etc/certs/default/srv-cert.pem",
                                      source / "etc/certs/default/srv-key.pem")
        tls_client = None
        try:
            wait_for_api(process, api_port)
            wait_for_port(process, cli_port)
            cli = Cli(cli_port)

            status, _, payload = api_request(api_port, "GET", "/api/status/ping")
            assert status == 200
            status_document = json.loads(payload)
            assert status_document["status"] == "ok"
            assert "version" in status_document and "uptime" in status_document
            libraries = status_document["libraries"]
            openssl = libraries["openssl"]
            assert openssl["version"].startswith("OpenSSL ")
            assert openssl["build_version"] and openssl["source"] == "external"
            assert openssl["linkage"] in ("static", "dynamic")
            if openssl["linkage"] == "dynamic":
                assert openssl["loaded_library"]
            ngtcp2 = libraries["ngtcp2"]
            if ngtcp2["enabled"]:
                assert ngtcp2["version"] and ngtcp2["source"] == "submodule"
                assert ngtcp2["linkage"] == "static" and ngtcp2["crypto_adapter"] == "ossl"
            else:
                assert ngtcp2["linkage"] == "disabled"

            status, headers, payload = api_request(
                api_port, "POST", "/api/authorize",
                body=json.dumps({"access_key": api_key}),
                headers={"Content-Type": "application/json"})
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

            status, headers, payload = api_request(
                api_port, "GET", "/api/authorize?key=must-not-be-consumed")
            assert status == 405, (status, payload)
            assert any(name.lower() == "allow" and value == "POST"
                       for name, value in headers)
            assert "use POST" in json.loads(payload)["error"]

            unavailable = cli.command_failed(
                "execute admin enrollment issue integration-admin")
            assert "save config" in unavailable
            cli.command_ok("save config")
            enrollment_output = cli.command_ok(
                "execute admin enrollment issue integration-admin")
            enrollment_tokens = re.findall(r"\b[0-9a-f]{64}\b", enrollment_output)
            assert len(enrollment_tokens) == 1, enrollment_output
            enrollment_token = enrollment_tokens[0]

            status, _, payload = api_request(
                api_port, "GET", "/api/admin/administrators",
                headers={"X-API-Key": administrator_api_key})
            assert status == 200, (status, payload)
            administrator_state = json.loads(payload)
            assert administrator_state["state"] == "ready"
            assert administrator_state["administrators"] == []
            assert administrator_state["revision"]
            assert administrator_state["content_hash"]

            administrator_password = "integration-administrator-password"
            enrollment_request = json.dumps({
                "enrollment_token": enrollment_token,
                "password": administrator_password,
            })
            status, _, payload = api_request(
                api_port, "POST", "/api/admin/enrollment/consume",
                body=enrollment_request,
                headers={
                    "Content-Type": "application/json",
                    "X-Smithproxy-Expected-Revision": administrator_state["revision"],
                    "X-Smithproxy-Archive-SHA256": administrator_state["content_hash"],
                })
            assert status == 200, (status, payload)
            enrollment = json.loads(payload)
            assert enrollment["state"] == "enrolled"
            assert enrollment["administrator"] == "integration-admin"

            status, login_headers, payload = api_request(
                api_port, "POST", "/api/login",
                body=("username=integration-admin&password=" + administrator_password),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert status == 200, (status, payload)
            login = json.loads(payload)
            assert login["csrf_token"]
            administrator_cookies = [
                value for name, value in login_headers
                if name.lower() == "set-cookie"
            ]
            assert len(administrator_cookies) == 2
            managed_headers = {
                "Content-Type": "application/json",
                "Cookie": "; ".join(
                    value.split(";", 1)[0] for value in administrator_cookies),
                "csrf_token": login["csrf_token"],
            }

            status, _, payload = api_request(
                api_port, "GET", "/api/admin/administrators",
                headers=managed_headers)
            assert status == 200, (status, payload)
            inventory = json.loads(payload)
            assert inventory["administrators"] == [
                {"name": "integration-admin", "enabled": True},
            ]

            peer_password = "integration-peer-original-password"
            create_headers = {
                **managed_headers,
                "X-Smithproxy-Expected-Revision": inventory["revision"],
                "X-Smithproxy-Archive-SHA256": inventory["content_hash"],
            }
            status, _, payload = api_request(
                api_port, "POST", "/api/admin/administrators",
                body=json.dumps({"name": "integration-peer", "password": peer_password}),
                headers=create_headers)
            assert status == 200, (status, payload)
            peer_state = json.loads(payload)
            assert peer_state["state"] == "created"

            disable_headers = {
                **managed_headers,
                "X-Smithproxy-Expected-Revision": peer_state["revision"],
                "X-Smithproxy-Archive-SHA256": peer_state["content_hash"],
            }
            status, _, payload = api_request(
                api_port, "PATCH", "/api/admin/administrators/enabled",
                body=json.dumps({"name": "integration-peer", "enabled": False}),
                headers=disable_headers)
            assert status == 200, (status, payload)
            peer_state = json.loads(payload)
            assert peer_state["state"] == "enabled_changed"

            status, _, payload = api_request(
                api_port, "POST", "/api/login",
                body=("username=integration-peer&password=" + peer_password),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert status == 401, (status, payload)

            enable_headers = {
                **managed_headers,
                "X-Smithproxy-Expected-Revision": peer_state["revision"],
                "X-Smithproxy-Archive-SHA256": peer_state["content_hash"],
            }
            status, _, payload = api_request(
                api_port, "PATCH", "/api/admin/administrators/enabled",
                body=json.dumps({"name": "integration-peer", "enabled": True}),
                headers=enable_headers)
            assert status == 200, (status, payload)
            peer_state = json.loads(payload)

            peer_password = "integration-peer-replacement-password"
            password_headers = {
                **managed_headers,
                "X-Smithproxy-Expected-Revision": peer_state["revision"],
                "X-Smithproxy-Archive-SHA256": peer_state["content_hash"],
            }
            status, _, payload = api_request(
                api_port, "PUT", "/api/admin/administrators/password",
                body=json.dumps({"name": "integration-peer", "password": peer_password}),
                headers=password_headers)
            assert status == 200, (status, payload)
            peer_state = json.loads(payload)
            assert peer_state["state"] == "password_changed"

            status, _, payload = api_request(
                api_port, "POST", "/api/login",
                body=("username=integration-peer&password=" + peer_password),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert status == 200, (status, payload)

            remove_headers = {
                **managed_headers,
                "X-Smithproxy-Expected-Revision": peer_state["revision"],
                "X-Smithproxy-Archive-SHA256": peer_state["content_hash"],
            }
            status, _, payload = api_request(
                api_port, "DELETE", "/api/admin/administrators",
                body=json.dumps({"name": "integration-peer"}),
                headers=remove_headers)
            assert status == 200, (status, payload)
            assert json.loads(payload)["state"] == "removed"

            status, _, payload = api_request(
                api_port, "POST", "/api/login",
                body=("username=integration-peer&password=" + peer_password),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert status == 401, (status, payload)

            status, _, payload = api_request(
                api_port, "POST", "/api/admin/enrollment/consume",
                body=enrollment_request,
                headers={
                    "Content-Type": "application/json",
                    "X-Smithproxy-Expected-Revision": enrollment["revision"],
                    "X-Smithproxy-Archive-SHA256": enrollment["content_hash"],
                })
            assert status == 403, (status, payload)
            assert json.loads(payload)["error"]["code"] == "invalid_enrollment_token"

            invalid_enrollment_request = json.dumps({
                "enrollment_token": "0" * 64,
                "password": "not-a-real-administrator-password",
            })
            status, _, payload = api_request(
                api_port, "POST", "/api/admin/enrollment/consume",
                body=invalid_enrollment_request,
                headers={"Content-Type": "application/json"})
            assert status == 400, (status, payload)
            assert (json.loads(payload)["error"]["code"] ==
                    "missing_administrator_precondition")

            status, _, payload = api_request(
                api_port, "POST", "/api/admin/enrollment/consume",
                body=invalid_enrollment_request,
                headers={
                    "Content-Type": "application/json",
                    "X-Smithproxy-Expected-Revision": "not-a-revision",
                    "X-Smithproxy-Archive-SHA256": "0" * 64,
                })
            assert status == 403, (status, payload)
            assert json.loads(payload)["error"]["code"] == "invalid_enrollment_token"

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
            if cli is not None:
                cli.sock.close()
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
