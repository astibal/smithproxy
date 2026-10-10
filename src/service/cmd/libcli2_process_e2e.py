#!/usr/bin/env python3
"""Process/socket smoke test for Smithproxy's libcli2 configuration CLI."""

from __future__ import annotations

import argparse
import http.server
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


TELNET = re.compile(rb"\xff[\xfb-\xfe].")
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    requests: list[tuple[str, bytes]] = []
    stall_started = threading.Event()
    release_stall = threading.Event()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.__class__.requests.append((self.path, self.rfile.read(length)))
        if self.path == "/drop":
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if self.path == "/stall":
            self.__class__.stall_started.set()
            self.__class__.release_stall.wait(timeout=15)
        code = 503 if self.path == "/failure" else 202
        if self.path == "/large":
            body = b"X" * (8 * 1024 * 1024 + 1)
        else:
            body = b"rejected" if code == 503 else b"accepted"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass


class HoldingTlsOrigin:
    def __init__(self, certificate: Path, key: Path):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.certificate = certificate
        self.key = key
        self.ready = threading.Event()
        self.release = threading.Event()
        self.error: Exception | None = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certificate, self.key)
            raw, _ = self.listener.accept()
            with raw, context.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(10)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = tls.recv(4096)
                    if not chunk:
                        raise AssertionError("TLS request closed before headers")
                    request.extend(chunk)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
                            b"Connection: keep-alive\r\n\r\nTLS-ACTIVE")
                self.ready.set()
                self.release.wait(timeout=15)
        except Exception as exception:
            self.error = exception
            self.ready.set()

    def close(self) -> None:
        self.release.set()
        self.listener.close()
        self.thread.join(timeout=5)
        if self.error is not None:
            raise self.error


class Cli:
    def __init__(self, port: int, verbose: bool = False):
        self.verbose = verbose
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.settimeout(0.15)
        self.transcript = bytearray()
        self.read()

    def read(self, wait: float = 0.1) -> str:
        time.sleep(wait)
        chunks = bytearray()
        while True:
            try:
                part = self.sock.recv(65536)
            except TimeoutError:
                break
            if not part:
                break
            chunks.extend(part)
        self.transcript.extend(chunks)
        decoded = TELNET.sub(b"", chunks).decode("utf-8", "replace")
        # The CLI deliberately colors prompts and selected values.  Assertions
        # operate on semantic output, not terminal presentation; otherwise an
        # escape inserted between two words can make a correct response fail.
        return ANSI.sub("", decoded)

    def command(self, line: str) -> str:
        self.sock.sendall(line.encode() + b"\r\n")
        output = self.read()
        if self.verbose:
            print(f">>> {line}\n{output}", end="")
        return output

    def command_ok(self, line: str) -> str:
        output = self.command(line)
        if "% command handler failed" in output:
            raise AssertionError(f"command failed: {line}\n{output}")
        return output

    def wait_for(self, needle: str, timeout: float = 5.0) -> str:
        deadline = time.monotonic() + timeout
        output = ""
        while time.monotonic() < deadline:
            output += self.read(0.05)
            if needle in output:
                return output
        raise AssertionError(f"timed out waiting for {needle!r} in:\n{output}")

    def command_failed(self, line: str) -> str:
        output = self.command(line)
        if "% command handler failed" not in output:
            raise AssertionError(f"command unexpectedly succeeded: {line}\n{output}")
        return output

    def tab(self, prefix: str) -> str:
        self.sock.sendall(prefix.encode() + b"\t")
        output = self.read()
        if self.verbose:
            print(f">>> {prefix}<TAB>\n{output}", end="")
        self.sock.sendall(b"\x15")  # discard the unfinished line
        self.read()
        return output


def replace_setting(text: str, name: str, value: str) -> str:
    pattern = rf"(?m)^(\s*{re.escape(name)}\s*=\s*).*$"
    result, count = re.subn(pattern, rf"\g<1>{value}", text, count=1)
    if count != 1:
        raise AssertionError(f"setting not found: {name}")
    return result


def wait_for_port(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, _ = process.communicate()
            raise AssertionError(f"Smithproxy exited early ({process.returncode}):\n{stdout}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("Smithproxy CLI port did not open")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def socks_connect(port: int, target_port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise AssertionError("SOCKS authentication negotiation failed")
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                 + target_port.to_bytes(2, "big"))
    response = bytearray()
    while len(response) < 10:
        chunk = sock.recv(10 - len(response))
        if not chunk:
            raise AssertionError(f"short SOCKS response: {bytes(response)!r}")
        response.extend(chunk)
    if response[:2] != b"\x05\x00":
        raise AssertionError(f"SOCKS CONNECT failed: {bytes(response)!r}")
    return sock


def require(output: str, needle: str) -> None:
    if needle not in output:
        raise AssertionError(f"expected {needle!r} in:\n{output}")


def reject(output: str, needle: str) -> None:
    if needle in output:
        raise AssertionError(f"unexpected {needle!r} in:\n{output}")


def config_check(binary: Path, config: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(
        [str(binary), "--config-check-only", "--config-file", str(config)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=30)
    if completed.returncode != 0 or "Config file check OK" not in completed.stdout:
        raise AssertionError(
            f"configuration matrix case failed ({completed.returncode}):\n"
            f"{completed.stdout[-8000:]}")
    return completed.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--port", type=int, default=59123)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()

    webhook = http.server.ThreadingHTTPServer(("127.0.0.1", 0), WebhookHandler)
    webhook_thread = threading.Thread(target=webhook.serve_forever, daemon=True)
    webhook_thread.start()
    webhook_port = webhook.server_address[1]

    with tempfile.TemporaryDirectory(prefix="smithproxy-libcli2-e2e-") as tmp_name:
        tmp = Path(tmp_name)
        config = tmp / "smithproxy.cfg"
        socks_port = free_port()
        shutil.copyfile(source / "etc/smithproxy.cfg", config)
        text = config.read_text()
        for name, value in (
            ("accept_tproxy", "FALSE;"),
            ("accept_redirect", "FALSE;"),
            ("accept_socks", "TRUE;"),
            ("certs_path", f'"{source / "etc/certs/default"}/";'),
            ("messages_dir", f'"{source / "etc/msg/en"}/";'),
            ("log_file", '"";'),
            ("log_console", "TRUE;"),
            ("sslkeylog_file", f'"{tmp}/sslkeylog.%s.log";'),
            ("write_payload_dir", f'"{tmp}/payload";'),
            ("allow_untrusted_issuers", "TRUE;"),
            ("allow_invalid_certs", "TRUE;"),
            ("allow_self_signed", "TRUE;"),
        ):
            text = replace_setting(text, name, value)
        text = replace_setting(text, "socks_workers", "1;")
        text = text.replace("socks_workers = 1;",
                            f'socks_workers = 1;\n    socks_port = "{socks_port}";', 1)
        text = text.replace("settings = {", "settings = {\n    accept_api = FALSE;", 1)
        text = text.replace(
            "settings = {",
            "settings = {\n"
            "    webhook = { enabled = true; "
            f'url = "http://127.0.0.1:{webhook_port}/default"; '
            "tls_verify = false; };",
            1,
        )
        # The legacy authentication profile section is optional in the stock
        # configuration, but it still has to survive configuration editing and
        # save/reload for backwards compatibility.
        text += '''
auth_profiles = {
    libcli2_compat_auth = {
        authenticate = true;
        resolve = false;
        identities = {
            integration_user = {
                detection_profile = "detect";
                content_profile = "default";
                tls_profile = "default";
                alg_dns_profile = "dns_default";
            };
        };
    };
};
'''
        text = re.sub(r"(?m)^(\s*port\s*=\s*)50000;", rf"\g<1>{args.port};", text, count=1)
        config.write_text(text)

        env = os.environ.copy()
        env["SMITHPROXY_PID_FILE"] = str(tmp / "smithproxy.pid")
        process = subprocess.Popen(
            [str(args.binary.resolve()), "--config-file", str(config)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        cli = None
        proxied = None
        origin = socket.socket()
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(5)
        origin_port = origin.getsockname()[1]
        origin_peer = None
        tls_origin = HoldingTlsOrigin(source / "etc/certs/default/srv-cert.pem",
                                      source / "etc/certs/default/srv-key.pem")
        tls_client = None
        try:
            wait_for_port(process, args.port)
            wait_for_port(process, socks_port)
            cli = Cli(args.port, args.verbose)
            require(cli.tab("en"), "enable")
            require(cli.command("enable"), "#")
            require(cli.command("disable"), ">")
            require(cli.command("en"), "#")
            require(cli.command_ok("show"), "Version:")
            require(cli.command_ok("show status"), "Total sessions:")
            require(cli.command_ok("execute events clear"), "Events cleared")
            require(cli.command_ok("show event list"), "events cleared by admin")
            require(cli.command_ok("execute kb print"), "Knowledgebase dump:")
            cli.command_ok("execute pcap rollover")
            require(cli.command_ok("debug show"), "baseProxy debug level:")
            require(cli.command_ok("debug term 6"), "logging level changed to 6")
            cli.command_ok("debug term reset")
            require(cli.command_ok("debug set cli 0"), "cli debug now OFF")
            # Exercise every debug command in query, set, reset and malformed
            # forms. These are operational recovery controls, so parser drift
            # must not first be discovered while troubleshooting production.
            for topic in ("ssl", "dns", "proxy"):
                cli.command_ok(f"debug {topic}")
                cli.command_ok(f"debug {topic} 4")
                cli.command_ok(f"debug {topic} reset")
                cli.command_failed(f"debug {topic} 11")
            cli.command_ok("debug level")
            cli.command_ok("debug level 4")
            cli.command_ok("debug level reset")
            cli.command_failed("debug level invalid")
            cli.command_ok("debug file")
            cli.command_ok("debug file 4")
            cli.command_ok("debug file reset")
            cli.command_failed("debug file invalid")
            require(cli.command_ok("debug set"), "Variable list:")
            require(cli.command_ok("debug set filter integration"),
                    "Logging context filter set")
            require(cli.command_ok("debug set filter"),
                    "Logging context filter deactivated")
            cli.command_ok("debug set all")
            require(cli.command_ok("debug set all 4"),
                    "all lightweight logger levels changed")
            cli.command_failed("debug set all 11")
            cli.command_failed("debug set definitely-not-a-topic")
            require(cli.command_ok("test dns genrequest example.test"), "DNS generated request:")
            output = cli.command_ok(
                f"test webhook http://127.0.0.1:{webhook_port}/success")
            if "Response: 202:accepted" not in output:
                output += cli.wait_for("Response: 202:accepted")
            require(output, "Response: 202:accepted")
            reject(output, "Response: -100:")
            output = cli.command_ok(
                f"test webhook http://127.0.0.1:{webhook_port}/failure")
            if "Response: 503:rejected" not in output:
                output += cli.wait_for("Response: 503:rejected")
            require(output, "Response: 503:rejected")
            reject(output, "Response: -100:")
            test_requests = [entry for entry in WebhookHandler.requests
                             if entry[0] in {"/success", "/failure"}]
            if test_requests != [
                    ("/success", b'{"key": "value"}'),
                    ("/failure", b'{"key": "value"}')]:
                raise AssertionError(f"unexpected webhook payloads: {WebhookHandler.requests!r}")

            with socket.socket() as unused:
                unused.bind(("127.0.0.1", 0))
                unavailable_port = unused.getsockname()[1]
            output = cli.command_ok(
                f"test webhook http://127.0.0.1:{unavailable_port}/unavailable")
            if "Response: 600:" not in output:
                output += cli.wait_for("Response: 600:")
            require(output, "Response: 600:")
            reject(output, "Response: -100:")

            output = cli.command_ok(
                f"test webhook http://127.0.0.1:{webhook_port}/drop")
            if "Response: 600:" not in output:
                output += cli.wait_for("Response: 600:")
            require(output, "Response: 600:")
            if [path for path, _ in WebhookHandler.requests].count("/drop") != 1:
                raise AssertionError("ambiguous POST failure was retried")

            output = cli.command_ok(
                f"test webhook http://127.0.0.1:{webhook_port}/large")
            if "Response: 600:webhook response exceeds configured limit" not in output:
                output += cli.wait_for(
                    "Response: 600:webhook response exceeds configured limit")
            require(output, "Response: 600:webhook response exceeds configured limit")
            diag_roots = cli.tab("diag ")
            for root in ("tls", "sig", "workers", "mem", "dns", "proxy", "writer", "capture", "api", "neighbor"):
                require(diag_roots, root)
            require(cli.command_ok("diag tls cache stats"), "certificate store")
            require(cli.command_ok("diag tls cache list"), "'pki.cert.mitm' certificate store entries")
            require(cli.command_ok("diag tls cache print"), "'pki.cert.mitm' certificate store entries")
            reject(cli.command_ok("diag tls cache clear"), "TLS certificate store unavailable")
            require(cli.command_ok("diag mem buffers stats"), "memory alloc")
            cli.command_ok("diag dns cache stats")
            cli.command_ok("diag proxy policy list")
            require(cli.command_ok("diag writer stats"), "Pending ops:")
            require(cli.command_ok("diag capture status"), "Capture enrichment:")
            require(cli.command_ok("diag capture schemas"), "smithproxy.tls.v1")
            require(cli.command_ok("diag api info"), "API keys")
            cli.command_ok("diag neighbor stats")

            # Keep one real proxied flow alive while querying diagnostics.  An
            # empty session list exercises command registration but not the
            # renderers, socket counters, policy labels, or worker traversal.
            proxied = socks_connect(socks_port, origin_port)
            proxied.sendall(b"libcli2 active session\n")
            origin_peer, _ = origin.accept()
            require(origin_peer.recv(4096).decode(), "libcli2 active session")

            tls_origin.start()
            tls_raw = socks_connect(socks_port, tls_origin.port)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE
            tls_client = tls_context.wrap_socket(
                tls_raw, server_hostname="integration.invalid")
            tls_client.sendall(
                b"GET /active HTTP/1.1\r\nHost: integration.invalid\r\n\r\n")
            tls_response = bytearray()
            while b"TLS-ACTIVE" not in tls_response:
                tls_response.extend(tls_client.recv(4096))
            if not tls_origin.ready.wait(timeout=5):
                raise AssertionError("TLS origin did not receive the request")
            if tls_origin.error is not None:
                raise tls_origin.error
            for diag_command in (
                "diag tls whitelist list", "diag tls whitelist stats",
                "diag tls crl list", "diag tls crl stats",
                "diag tls verify list", "diag tls verify stats", "diag tls verify clear",
                "diag tls ticket list", "diag tls ticket stats", "diag tls ticket clear",
                "diag tls ca reload", "diag sig list",
                "diag workers proxy list", "diag workers pool list",
                "diag mem buffers stats", "diag mem udp stats",
                "diag mem trace list", "diag mem trace mark",
                "diag dns cache list", "diag dns cache stats", "diag dns cache clear",
                "diag dns domain list", "diag dns domain clear",
                "diag proxy policy list", "diag proxy session list",
                "diag proxy session list-nonames", "diag proxy session clear",
                "diag proxy session tls-info", "diag proxy session ssh-info",
                "diag proxy session active", "diag proxy io list",
                "diag proxy session list active tls io-all nonames ips 8 ignored",
                "diag proxy quic list",
                "diag writer stats", "diag capture status", "diag capture schemas", "diag api info",
                "diag neighbor list", "diag neighbor stats", "diag neighbor clear",
                "diag neighbor webhook-update-all", "diag neighbor webhook-update-ping",
            ):
                cli.command_ok(diag_command)
            proxied.close()
            proxied = None
            origin_peer.close()
            origin_peer = None
            tls_client.close()
            tls_client = None
            tls_origin.close()
            cli.command_ok("diag tls whitelist insert_fingerprint 00:11 1")
            cli.command_ok("diag tls whitelist insert_l4 127.0.0.1:127.0.0.1:443 1")
            cli.command_ok("diag tls whitelist clear")
            require(cli.command_ok("diag neighbor tag missing +test"), "not found")
            require(cli.command_ok("diag neighbor webhook-update missing"), "not found")
            for diag_command in (
                "diag tls whitelist insert_fingerprint",
                "diag tls whitelist insert_l4",
                "diag neighbor tag",
                "diag neighbor webhook-update",
            ):
                cli.command_failed(diag_command)
            require(cli.command("configure terminal"), "(config:/)")

            cli.command_ok("edit address_objects")
            require(cli.command_ok("show"), "address_objects")
            cli.command_ok("add libcli2_e2e_net")
            require(cli.tab("edit libcli2_e2e"), "libcli2_e2e_net")
            cli.command_ok("edit libcli2_e2e_net")
            cli.command_ok("set type cidr")
            cli.command_ok("set value 192.0.2.0/24")
            cli.command_ok("end")
            cli.command_ok("end")
            require(cli.command_ok("show config address_objects"), "libcli2_e2e_net")

            require(cli.command_ok("edit policy"), "(config:/policy)")
            require(cli.command_ok("show"), "policy")
            require(cli.tab("edit "), "[0]")
            require(cli.tab("add "), "Optional entry name")
            cli.command_ok("add")
            completed = cli.tab("edit [")
            indexes = re.findall(r"\[(\d+)\]", completed)
            if not indexes:
                raise AssertionError(f"cannot find added policy index in:\n{completed}")
            index = str(max(map(int, indexes)))
            require(cli.command_ok(f"edit [{index}]"), f"(config:/policy.[{index}])")
            require(cli.command_ok("show"), "policy")
            policy_children = cli.tab("edit ")
            if any(value in policy_children for value in ("src", "sport", "dst", "dport", "features")):
                raise AssertionError(f"value array offered as editable section:\n{policy_children}")
            require(cli.command_failed("edit src"), "unknown configuration section")
            cli.command_ok("toggle src libcli2_e2e_net")
            cli.command_ok("end")
            require(cli.command_ok(f"show config policy {index}"), "libcli2_e2e_net")
            cli.command_ok(f"move [{index}] top")
            cli.command_ok("end")

            cli.command_ok("edit tls_profiles")
            cli.command_ok("add libcli2_e2e_tls")
            cli.command_ok("edit libcli2_e2e_tls")
            cli.command_ok("set inspect true")
            cli.command_ok("set client_hello_timeout 1234")
            cli.command_ok("set handshake_timeout 5678")
            cli.command_ok("end")
            cli.command_ok("end")

            cli.command_ok("edit ssh_profiles")
            cli.command_ok("add libcli2_e2e_ssh")
            cli.command_ok("edit libcli2_e2e_ssh")
            require(cli.command_ok("set shell reject"), "config:/ssh_profiles.libcli2_e2e_ssh")
            cli.command_ok("set exec pass")
            cli.command_ok("set subsystem reject")
            cli.command_ok("set pty pass")
            cli.command_ok("set environment reject")
            cli.command_ok("set local_forward pass")
            cli.command_ok("set remote_forward reject")
            cli.command_ok("set x11 reject")
            cli.command_ok("set agent reject")
            cli.command_ok("end")
            require(cli.command_ok("show config ssh_profiles"), "libcli2_e2e_ssh")
            cli.command_ok("remove libcli2_e2e_ssh")
            cli.command_ok("end")

            # Exercise every named configuration-object constructor which is
            # supported by the CLI, then keep the objects through the real
            # save/reload below.  This catches serializer/loader drift which a
            # simple in-memory edit cannot expose.
            named_objects = (
                ("proto_objects", "libcli2_e2e_proto", ("set id 253",)),
                ("detection_profiles", "libcli2_e2e_detection", ("set mode 0",)),
                ("content_profiles", "libcli2_e2e_content",
                 ("set write_payload true",)),
                ("alg_dns_profiles", "libcli2_e2e_dns",
                 ("set match_request_id true", "set randomize_id true")),
                ("auth_profiles", "libcli2_e2e_auth",
                 ("set authenticate true", "set resolve false")),
                ("routing", "libcli2_e2e_route",
                 ("toggle dnat_address any", "toggle dnat_port all",
                  "set dnat_lb_method sticky-l4", "set rewrite_sni old.example",
                  "set rewrite_sni_to new.example")),
            )
            for section, name, commands in named_objects:
                cli.command_ok(f"edit {section}")
                cli.command_ok(f"add {name}")
                cli.command_ok(f"edit {name}")
                for command in commands:
                    cli.command_ok(command)
                cli.command_ok("end")
                cli.command_ok("end")
                require(cli.command_ok(f"show config {section}"), name)

            blocked = cli.command("edit address_objects")
            require(blocked, "address_objects")
            require(cli.command_failed("remove libcli2_e2e_net"), "used by")
            require(cli.tab("edit libcli2_e2e"), "libcli2_e2e_net")
            cli.command_ok("end")
            cli.command_ok("edit policy")
            cli.command_ok("remove [0]")
            cli.command_ok("end")
            cli.command_ok("edit address_objects")
            cli.command_ok("remove libcli2_e2e_net")
            if "libcli2_e2e_net" in cli.tab("edit libcli2_e2e"):
                raise AssertionError("removed address object is still offered by completion")
            require(cli.command("where"), "address_objects")
            cli.command_ok("end")
            cli.command_ok("end")
            require(cli.command_ok("save config"), "config saved successfully")
            saved_config = config.read_text()
            tls_profile = re.search(
                r"libcli2_e2e_tls\s*=\s*\{(?P<body>.*?)\}\s*;?",
                saved_config, flags=re.DOTALL)
            if tls_profile is None:
                raise AssertionError("saved configuration lost the TLS profile")
            require(tls_profile.group("body"), "client_hello_timeout = 1234")
            require(tls_profile.group("body"), "handshake_timeout = 5678")
            require(cli.command_ok("execute reload"), "Configuration file reloaded")
            for section, name, _ in named_objects:
                require(cli.command_ok(f"show config {section}"), name)
            require(cli.command_ok("show status"), "Total sessions:")
            cli.command_ok(f"test webhook http://127.0.0.1:{webhook_port}/stall")
            if not WebhookHandler.stall_started.wait(timeout=3):
                raise AssertionError("stalled webhook request did not start")
            shutdown_started = time.monotonic()
            require(cli.command_ok("execute shutdown"), "terminating smithproxy")
            process.wait(timeout=4)
            if time.monotonic() - shutdown_started >= 4:
                raise AssertionError("active webhook delayed Smithproxy shutdown")

            # Re-run the saved configuration as an old schema.  This exercises
            # every sequential schema migration against a complete, known-good
            # configuration and proves that the upgraded result starts again.
            cli.sock.close()
            cli = None
            if process.stdout:
                process.stdout.read()
            upgraded_text, replacements = re.subn(
                r"(?m)^(\s*schema\s*=\s*)\d+(\s*;?\s*)$", r"\g<1>1000\2",
                config.read_text(), count=1)
            if replacements != 1:
                raise AssertionError("saved configuration has no schema marker")
            upgraded_text, replacements = re.subn(
                r'(?m)^(\s*version\s*=\s*)"[^"]*"(\s*;?\s*)$',
                r'\g<1>"0.9.22"\2', upgraded_text, count=1)
            if replacements != 1:
                raise AssertionError("saved configuration has no version marker")
            config.write_text(upgraded_text)

            process = subprocess.Popen(
                [str(args.binary.resolve()), "--config-file", str(config)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            wait_for_port(process, args.port)
            cli = Cli(args.port, args.verbose)
            require(cli.command("enable"), "#")
            require(cli.command_ok("execute shutdown"), "terminating smithproxy")
            process.wait(timeout=10)
            schema = re.search(
                r"(?m)^\s*schema\s*=\s*(\d+)\s*;?\s*$", config.read_text())
            if schema is None or int(schema.group(1)) <= 1000:
                raise AssertionError("schema migration did not persist its result")
            if not (tmp / "smithproxy.cfg.0.9.22.bak.cfg").is_file():
                raise AssertionError("version migration did not preserve a backup")

            # One deliberately mixed legacy/degraded configuration exercises
            # compatibility loaders and fail-closed policy diagnostics. The
            # daemon accepts the file but marks unusable rules degraded or
            # disabled; a crash or whole-file rejection is a regression.
            matrix = config.read_text()
            matrix, count = re.subn(
                r"(address_objects\s*=\s*\{)",
                r"\1\n"
                "    legacy_cidr = { type = 0; cidr = \"198.51.100.0/24\"; };\n"
                "    legacy_fqdn = { type = 1; fqdn = \"legacy.invalid\"; };\n"
                "    legacy_unknown = { type = 99; };\n"
                "    invalid_new = { type = \"unknown\"; value = \"bad\"; };",
                matrix, count=1)
            if count != 1:
                raise AssertionError("address_objects matrix insertion failed")
            matrix, count = re.subn(
                r"(port_objects\s*=\s*\{)",
                r"\1\n"
                "    reversed_range = { start = 9000; end = 8000; };\n"
                "    incomplete_range = { start = 7; };",
                matrix, count=1)
            if count != 1:
                raise AssertionError("port_objects matrix insertion failed")
            matrix, count = re.subn(
                r"(proto_objects\s*=\s*\{)",
                r"\1\n    incomplete_proto = { };", matrix, count=1)
            if count != 1:
                raise AssertionError("proto_objects matrix insertion failed")
            matrix, count = re.subn(
                r"(identities\s*=\s*\{)",
                r"\1\n"
                "            broken_identity = { detection_profile = \"missing\"; "
                "content_profile = \"missing\"; tls_profile = \"missing\"; "
                "alg_dns_profile = \"missing\"; };",
                matrix, count=1)
            if count != 1:
                raise AssertionError("auth identity matrix insertion failed")
            matrix, count = re.subn(
                r"(policy\s*=\s*\()",
                r"\1\n"
                "    { name = \"scalar-compat\"; proto = \"tcp\"; src = \"any\"; "
                "sport = \"all\"; dst = \"any\"; dport = \"all\"; "
                "features = [ \"statistics\" ]; action = \"accept\"; nat = \"none\"; "
                "tls_profile = \"default\"; detection_profile = \"detect\"; "
                "content_profile = \"default\"; alg_dns_profile = \"dns_default\"; "
                "routing = \"none\"; },\n"
                "    { name = \"hard-error\"; proto = \"missing\"; "
                "src = [ \"missing\" ]; sport = [ \"missing\" ]; "
                "dst = [ \"missing\" ]; dport = [ \"missing\" ]; "
                "features = [ \"missing\" ]; action = \"unexpected\"; "
                "nat = \"unexpected\"; },\n"
                "    { name = \"soft-error\"; proto = \"tcp\"; src = [ \"any\" ]; "
                "sport = [ \"all\" ]; dst = [ \"any\" ]; dport = [ \"all\" ]; "
                "action = \"accept\"; nat = \"auto\"; "
                "tls_profile = \"missing\"; detection_profile = \"missing\"; "
                "content_profile = \"missing\"; alg_dns_profile = \"missing\"; "
                "script_profile = \"missing\"; auth_profile = \"removed\"; "
                "routing = \"missing\"; },",
                matrix, count=1)
            if count != 1:
                raise AssertionError("policy matrix insertion failed")
            matrix_config = tmp / "smithproxy-loader-matrix.cfg"
            matrix_config.write_text(matrix)
            for marker in ("legacy_cidr", "incomplete_range", "hard-error", "soft-error"):
                require(matrix, marker)
            config_check(args.binary.resolve(), matrix_config, env)

            # Settings are process-global, so exercise mutually exclusive
            # fallback branches in independent config-check processes.
            settings_matrix = config.read_text()
            settings_matrix, count = re.subn(
                r"nameservers\s*=\s*(?:\[[^]]*\]|\([^)]*\))\s*;?",
                'nameservers = [ "not-an-address", "::1", "127.0.0.1" ];',
                settings_matrix, count=1)
            if count != 1:
                raise AssertionError("nameserver matrix replacement failed")
            settings_matrix = settings_matrix.replace(
                "settings = {", "settings = {\n    auth_portal = { enabled = true; };", 1)
            api_port_pattern = (
                r"(http_api\s*=\s*\{.*?\bport\s*=\s*)\d+(\s*;?)"
            )
            settings_matrix, count = re.subn(
                api_port_pattern, r"\g<1>1024\2", settings_matrix,
                count=1, flags=re.DOTALL)
            if count != 1:
                raise AssertionError("HTTP API port matrix replacement failed")
            settings_config = tmp / "smithproxy-settings-matrix.cfg"
            settings_config.write_text(settings_matrix)
            config_check(args.binary.resolve(), settings_config, env)

            empty_dns = config.read_text()
            empty_dns, count = re.subn(
                r"nameservers\s*=\s*(?:\[[^]]*\]|\([^)]*\))\s*;?",
                "nameservers = [ ];", empty_dns, count=1)
            if count != 1:
                raise AssertionError("empty nameserver matrix replacement failed")
            empty_dns_config = tmp / "smithproxy-empty-dns-matrix.cfg"
            empty_dns_config.write_text(empty_dns)
            config_check(args.binary.resolve(), empty_dns_config, env)

            print("PASS: real socket show/debug/test/save/reload/shutdown + config mutations + "
                  "schema migration + compatibility/error/settings matrices")
        finally:
            if proxied is not None:
                proxied.close()
            if origin_peer is not None:
                origin_peer.close()
            if tls_client is not None:
                tls_client.close()
            tls_origin.close()
            origin.close()
            if cli is not None:
                cli.sock.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.stdout:
                tail = process.stdout.read()
                if tail:
                    print("--- smithproxy output ---")
                    print(tail[-4000:])
            WebhookHandler.release_stall.set()
            webhook.shutdown()
            webhook.server_close()
            webhook_thread.join(timeout=5)


if __name__ == "__main__":
    main()
