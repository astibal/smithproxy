#!/usr/bin/env python3
"""Exercise Smithproxy CLI mutations while external traffic is flowing."""

from __future__ import annotations

import argparse
import random
import socket
import time

from libcli2_process_e2e import Cli, TELNET, require


class RemoteCli(Cli):
    def __init__(self, host: str, port: int, verbose: bool = False):
        self.verbose = verbose
        self.command_count = 0
        self.sock = socket.create_connection((host, port), timeout=5)
        self.sock.settimeout(0.75)
        self.transcript = bytearray()
        self.read()

    def read(self, wait: float = 0.1) -> str:
        """Tolerate a busy proxy, but finish promptly after the reply goes idle."""
        del wait
        deadline = time.monotonic() + 8.0
        chunks = bytearray()
        while time.monotonic() < deadline:
            self.sock.settimeout(min(0.75, deadline - time.monotonic()))
            try:
                part = self.sock.recv(65536)
            except (TimeoutError, socket.timeout):
                if chunks:
                    break
                continue
            if not part:
                break
            chunks.extend(part)
        self.transcript.extend(chunks)
        return TELNET.sub(b"", chunks).decode("utf-8", "replace")

    def command(self, line: str) -> str:
        self.command_count += 1
        return super().command(line)


DIAGS = (
    "show status", "diag tls cache stats", "diag tls cache list",
    "diag tls ticket stats", "diag tls verify stats", "diag tls whitelist stats",
    "diag workers proxy list 7", "diag workers pool list", "diag mem buffers stats",
    "diag mem udp stats", "diag mem objects stats", "diag dns cache stats",
    "diag proxy policy list", "diag proxy session list", "diag proxy session tls-info",
    "diag proxy session active", "diag proxy io list", "diag writer stats",
    "diag neighbor stats",
)

EXPECTED_COVERAGE = {
    "add:named", "add:ordered", "edit", "set:string", "set:int", "set:bool",
    "toggle", "move", "remove:named", "remove:ordered", "show", "diag:all",
    "save", "reload", "nested:content_rules",
}


def ok(cli: RemoteCli, command: str) -> str:
    output = cli.command(command)
    if not output:
        raise AssertionError(f"empty CLI response: {command}")
    if "% command handler failed" in output or "unknown command" in output:
        raise AssertionError(f"command failed: {command}\n{output}")
    return output


def add_named(cli: RemoteCli, section: str, name: str, settings: tuple[tuple[str, str], ...] = ()) -> None:
    ok(cli, f"edit {section}")
    ok(cli, f"add {name}")
    if settings:
        ok(cli, f"edit {name}")
        for key, value in settings:
            ok(cli, f"set {key} {value}")
        ok(cli, "end")
    ok(cli, "end")


def remove_named(cli: RemoteCli, section: str, name: str) -> None:
    ok(cli, f"edit {section}")
    ok(cli, f"remove {name}")
    ok(cli, "end")


def one_iteration(cli: RemoteCli, rng: random.Random, serial: int, coverage: set[str],
                  mutate_signatures: bool = True) -> None:
    tag = f"live_{serial:06d}_{rng.randrange(1 << 24):06x}"
    names = {
        "address_objects": tag + "_addr",
        "port_objects": tag + "_port",
        "proto_objects": tag + "_proto",
        "detection_profiles": tag + "_detect",
        "content_profiles": tag + "_content",
        "tls_ca": tag + "_ca",
        "tls_profiles": tag + "_tls",
        "alg_dns_profiles": tag + "_dns",
        "auth_profiles": tag + "_auth",
        "routing": tag + "_route",
    }

    ok(cli, "configure terminal")
    coverage.update(("edit", "set:string", "set:int", "set:bool"))
    # Scalar round trips cover live apply outside collection CRUD.
    ok(cli, "edit settings")
    ok(cli, "set ssl_autodetect false")
    ok(cli, "set ssl_autodetect true")
    ok(cli, "end")
    ok(cli, "edit debug")
    ok(cli, "set log_sockets true")
    ok(cli, "set log_sockets false")
    ok(cli, "end")
    add_named(cli, "address_objects", names["address_objects"], (("type", "cidr"), ("value", "198.18.20.2/32")))
    coverage.add("add:named")
    add_named(cli, "port_objects", names["port_objects"], (("start", "443"), ("end", "8080")))
    add_named(cli, "proto_objects", names["proto_objects"], (("id", "6"),))
    add_named(cli, "detection_profiles", names["detection_profiles"], (("mode", "1"),))
    add_named(cli, "content_profiles", names["content_profiles"])
    add_named(cli, "tls_ca", names["tls_ca"])
    add_named(cli, "tls_profiles", names["tls_profiles"], (("inspect", "true"),))
    add_named(cli, "alg_dns_profiles", names["alg_dns_profiles"])
    add_named(cli, "auth_profiles", names["auth_profiles"], (("authenticate", "false"), ("resolve", "true")))
    add_named(cli, "routing", names["routing"])

    # Exercise nested ordered structures as well as their parent profiles.
    ok(cli, "edit content_profiles")
    ok(cli, f"edit {names['content_profiles']}")
    ok(cli, "edit content_rules")
    ok(cli, "add")
    coverage.update(("add:ordered", "nested:content_rules"))
    ok(cli, "remove [0]")
    ok(cli, "end")
    ok(cli, "end")
    ok(cli, "end")

    for signature_section in (() if not mutate_signatures else ("starttls_signatures", "detection_signatures")):
        ok(cli, f"edit {signature_section}")
        ok(cli, f"add {tag}_{signature_section}")
        completed = cli.tab("edit [")
        import re
        signature_indexes = [int(value) for value in re.findall(r"\[(\d+)\]", completed)]
        if not signature_indexes:
            raise AssertionError(f"new signature index missing: {completed}")
        signature_index = max(signature_indexes)
        ok(cli, f"edit [{signature_index}]")
        ok(cli, "edit flow")
        ok(cli, "add")
        coverage.add("add:ordered")
        ok(cli, "remove [0]")
        ok(cli, "end")
        ok(cli, "end")
        ok(cli, f"remove [{signature_index}]")
        ok(cli, "end")

    ok(cli, "edit policy")
    ok(cli, "add")
    coverage.add("add:ordered")
    indexes = []
    completed = cli.tab("edit [")
    import re
    indexes = [int(value) for value in re.findall(r"\[(\d+)\]", completed)]
    if not indexes:
        raise AssertionError(f"new policy index missing: {completed}")
    index = max(indexes)
    ok(cli, f"edit [{index}]")
    for key, value in (
        ("disabled", "false"), ("name", tag), ("proto", names["proto_objects"]),
        ("action", "accept"), ("nat", "auto"),
        ("tls_profile", names["tls_profiles"]),
        ("detection_profile", names["detection_profiles"]),
        ("content_profile", names["content_profiles"]),
        ("auth_profile", names["auth_profiles"]),
        ("alg_dns_profile", names["alg_dns_profiles"]),
        ("routing", names["routing"]),
    ):
        ok(cli, f"set {key} {value}")
    ok(cli, f"toggle src {names['address_objects']}")
    ok(cli, f"toggle dst {names['address_objects']}")
    ok(cli, f"toggle sport {names['port_objects']}")
    ok(cli, f"toggle dport {names['port_objects']}")
    coverage.add("toggle")
    ok(cli, "end")
    ok(cli, f"move [{index}] top")
    coverage.add("move")
    ok(cli, "end")
    ok(cli, "end")

    for command in DIAGS:
        ok(cli, command)
    coverage.update(("diag:all", "show"))

    ok(cli, "configure terminal")
    ok(cli, "edit policy")
    # The just-created rule was moved to the first position.
    ok(cli, "remove [0]")
    coverage.add("remove:ordered")
    ok(cli, "end")
    for section in reversed(tuple(names)):
        remove_named(cli, section, names[section])
    coverage.add("remove:named")
    ok(cli, "end")

    # Exercise persistence only at a clean transaction boundary.
    if serial % 3 == 0:
        ok(cli, "save config")
        ok(cli, "execute reload")
        coverage.update(("save", "reload"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=50000)
    parser.add_argument("--duration", type=float, default=600)
    parser.add_argument("--seed", type=int, default=0x51A7)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--skip-signatures", action="store_true",
                        help="skip known-racy live signature-tree reloads")
    args = parser.parse_args()
    rng = random.Random(args.seed)
    cli = RemoteCli(args.host, args.port, args.verbose)
    started = time.monotonic()
    serial = 0
    coverage: set[str] = set()
    try:
        require(ok(cli, "enable"), "#")
        while time.monotonic() - started < args.duration:
            one_iteration(cli, rng, serial, coverage, not args.skip_signatures)
            serial += 1
            print(f"PROGRESS: iterations={serial}, cli_commands={cli.command_count}, "
                  f"elapsed={time.monotonic() - started:.1f}s", flush=True)
        missing = EXPECTED_COVERAGE - coverage
        if missing:
            raise AssertionError("missing CLI coverage: " + ", ".join(sorted(missing)))
        print(f"PASS: {serial} live mutation iterations in {time.monotonic() - started:.1f}s, "
              f"seed={args.seed}, coverage={len(coverage)}/{len(EXPECTED_COVERAGE)}, "
              f"cli_commands={cli.command_count}")
    finally:
        cli.sock.close()


if __name__ == "__main__":
    main()
