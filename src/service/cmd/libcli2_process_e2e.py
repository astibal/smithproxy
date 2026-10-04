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


def require(output: str, needle: str) -> None:
    if needle not in output:
        raise AssertionError(f"expected {needle!r} in:\n{output}")


def reject(output: str, needle: str) -> None:
    if needle in output:
        raise AssertionError(f"unexpected {needle!r} in:\n{output}")


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
        shutil.copyfile(source / "etc/smithproxy.cfg", config)
        text = config.read_text()
        for name, value in (
            ("accept_tproxy", "FALSE;"),
            ("accept_redirect", "FALSE;"),
            ("accept_socks", "FALSE;"),
            ("certs_path", f'"{source / "etc/certs/default"}/";'),
            ("messages_dir", f'"{source / "etc/msg/en"}/";'),
            ("log_file", '"";'),
            ("log_console", "TRUE;"),
            ("sslkeylog_file", f'"{tmp}/sslkeylog.%s.log";'),
            ("write_payload_dir", f'"{tmp}/payload";'),
        ):
            text = replace_setting(text, name, value)
        text = text.replace("settings = {", "settings = {\n    accept_api = FALSE;", 1)
        text = text.replace(
            "settings = {",
            "settings = {\n"
            "    webhook = { enabled = true; "
            f'url = "http://127.0.0.1:{webhook_port}/default"; '
            "tls_verify = false; };",
            1,
        )
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
        try:
            wait_for_port(process, args.port)
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
            for root in ("tls", "sig", "workers", "mem", "dns", "proxy", "writer", "api", "neighbor"):
                require(diag_roots, root)
            require(cli.command_ok("diag tls cache stats"), "certificate store")
            require(cli.command_ok("diag tls cache list"), "'pki.cert.mitm' certificate store entries")
            require(cli.command_ok("diag tls cache print"), "'pki.cert.mitm' certificate store entries")
            reject(cli.command_ok("diag tls cache clear"), "TLS certificate store unavailable")
            require(cli.command_ok("diag mem buffers stats"), "memory alloc")
            cli.command_ok("diag dns cache stats")
            cli.command_ok("diag proxy policy list")
            require(cli.command_ok("diag writer stats"), "Pending ops:")
            require(cli.command_ok("diag api info"), "API keys")
            cli.command_ok("diag neighbor stats")
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
                "diag proxy session tls-info", "diag proxy session active", "diag proxy io list",
                "diag writer stats", "diag api info",
                "diag neighbor list", "diag neighbor stats", "diag neighbor clear",
                "diag neighbor webhook-update-all", "diag neighbor webhook-update-ping",
            ):
                cli.command_ok(diag_command)
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
            cli.command_ok("end")
            cli.command_ok("remove libcli2_e2e_tls")
            cli.command_ok("end")

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
            require(cli.command_ok("execute reload"), "Configuration file reloaded")
            require(cli.command_ok("show status"), "Total sessions:")
            cli.command_ok(f"test webhook http://127.0.0.1:{webhook_port}/stall")
            if not WebhookHandler.stall_started.wait(timeout=3):
                raise AssertionError("stalled webhook request did not start")
            shutdown_started = time.monotonic()
            require(cli.command_ok("execute shutdown"), "terminating smithproxy")
            process.wait(timeout=4)
            if time.monotonic() - shutdown_started >= 4:
                raise AssertionError("active webhook delayed Smithproxy shutdown")
            print("PASS: real socket show/debug/test/save/reload/shutdown + config mutations")
        finally:
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
