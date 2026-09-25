#!/usr/bin/env python3
"""Stateful black-box fuzzer for the Smithproxy libcli2 socket interface."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time

from libcli2_process_e2e import replace_setting, wait_for_port


BASE_COMMANDS = (
    b"show", b"show status", b"show config", b"enable", b"disable", b"end", b"where",
    b"configure terminal", b"edit policy", b"edit [0]", b"edit address_objects",
    b"add", b"remove [0]", b"move [0] top", b"set name fuzz", b"toggle src any",
    b"debug show", b"debug term reset", b"debug set cli 0",
    b"diag tls cache stats", b"diag tls cache list", b"diag tls whitelist list",
    b"diag mem trace list",
    b"diag dns cache list", b"diag proxy policy list", b"diag proxy session list",
    b"diag workers proxy list", b"diag identity user list", b"diag neighbor list",
    b"test dns genrequest example.test",
)

TOKENS = (
    b"", b" ", b"\t", b"?", b"-1", b"0", b"1", b"2147483647", b"2147483648",
    b"4294967295", b"999999999999999999999999999", b"[", b"]", b"[0]", b"[-1]",
    b"[999999999999]", b".", b"..", b"/", b"//", b"*", b"%", b"0x0", b"0xdeadbeef",
    b"'", b'"', b"''", b'""', b"\\", b"\\x00", b"${x}", b";", b"|", b"&",
    b"\xc3\xa9", b"\xf0\x9f\x92\xa5", b"\xff", b"\x00",
)


def mutate(rng: random.Random, base: bytes) -> bytes:
    data = bytearray(base)
    for _ in range(rng.randint(1, 5)):
        operation = rng.randrange(7)
        pos = rng.randrange(len(data) + 1) if data else 0
        if operation == 0 and data:
            del data[rng.randrange(len(data))]
        elif operation == 1:
            data[pos:pos] = rng.choice(TOKENS)
        elif operation == 2 and data:
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif operation == 3:
            data[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        elif operation == 4 and data:
            begin = rng.randrange(len(data))
            data[pos:pos] = data[begin:begin + rng.randint(1, 32)]
        elif operation == 5:
            data.extend(b" " + rng.choice(TOKENS))
        else:
            data = bytearray(rng.choice(BASE_COMMANDS))
    return bytes(data)


def make_case(rng: random.Random, index: int) -> bytes:
    if index % 127 == 0:
        return rng.choice((b"A", b" ", b"[", b'"')) * rng.choice((255, 1024, 4096, 8192))
    if index % 41 == 0:
        return rng.choice(BASE_COMMANDS) + rng.choice((b"\t", b"?", b"\x15", b"\x7f", b"\x1b[A"))
    return mutate(rng, rng.choice(BASE_COMMANDS))


def drain(sock: socket.socket, timeout: float = 0.01) -> bytes:
    sock.settimeout(timeout)
    result = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, BlockingIOError):
            break
        if not chunk:
            raise ConnectionError("CLI closed the connection")
        result.extend(chunk)
        if len(result) > 4 * 1024 * 1024:
            break
    return bytes(result)


def write_reproducer(seed: int, cases: list[bytes], reason: BaseException) -> Path:
    path = Path(f"/tmp/smithproxy-cli-fuzz-failure-{seed}.txt")
    lines = [f"seed={seed}", f"reason={reason!r}"]
    lines.extend(f"{n}: {case!r}" for n, case in enumerate(cases))
    path.write_text("\n".join(lines) + "\n")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--port", type=int, default=59124)
    parser.add_argument("--cases", type=int, default=5000)
    parser.add_argument("--duration", type=float, default=0.0,
                        help="run for this many seconds instead of stopping at --cases")
    parser.add_argument("--seed", type=int, default=0xC112)
    args = parser.parse_args()
    source = args.source.resolve()
    rng = random.Random(args.seed)
    history: list[bytes] = []

    with tempfile.TemporaryDirectory(prefix="smithproxy-libcli2-fuzz-") as tmp_name:
        tmp = Path(tmp_name)
        config = tmp / "smithproxy.cfg"
        shutil.copyfile(source / "etc/smithproxy.cfg", config)
        text = config.read_text()
        for name, value in (
            ("accept_tproxy", "FALSE;"), ("accept_redirect", "FALSE;"), ("accept_socks", "FALSE;"),
            ("certs_path", f'"{source / "etc/certs/default"}/";'),
            ("messages_dir", f'"{source / "etc/msg/en"}/";'),
            ("log_file", '"";'), ("log_console", "TRUE;"),
            ("sslkeylog_file", f'"{tmp}/sslkeylog.%s.log";'),
            ("write_payload_dir", f'"{tmp}/payload";'),
        ):
            text = replace_setting(text, name, value)
        text = text.replace("settings = {", "settings = {\n    accept_api = FALSE;", 1)
        text = re.sub(r"(?m)^(\s*port\s*=\s*)50000;", rf"\g<1>{args.port};", text, count=1)
        config.write_text(text)

        env = os.environ.copy()
        env["SMITHPROXY_PID_FILE"] = str(tmp / "smithproxy.pid")
        process = subprocess.Popen(
            [str(args.binary.resolve()), "--config-file", str(config)], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        sock: socket.socket | None = None
        reconnects = 0
        try:
            wait_for_port(process, args.port)
            sock = socket.create_connection(("127.0.0.1", args.port), timeout=3)
            drain(sock, 0.1)
            sock.sendall(b"enable\r\n")
            drain(sock, 0.1)

            started = time.monotonic()
            index = 0
            while (not args.duration and index < args.cases) or (
                args.duration and time.monotonic() - started < args.duration
            ):
                case = make_case(rng, index)
                history.append(case)
                if len(history) > 200:
                    history.pop(0)
                try:
                    sock.sendall(case + b"\r\n")
                    drain(sock)
                except (BrokenPipeError, ConnectionError, ConnectionResetError, TimeoutError):
                    if process.poll() is not None:
                        raise RuntimeError(f"Smithproxy exited with status {process.returncode}")
                    sock.close()
                    sock = socket.create_connection(("127.0.0.1", args.port), timeout=3)
                    drain(sock, 0.1)
                    sock.sendall(b"enable\r\n")
                    drain(sock, 0.1)
                    reconnects += 1
                if process.poll() is not None:
                    raise RuntimeError(f"Smithproxy exited with status {process.returncode}")
                if index % 100 == 99:
                    sock.sendall(b"\x03\x15end\r\nend\r\nenable\r\n")
                    drain(sock, 0.05)
                index += 1
            elapsed = time.monotonic() - started
            print(f"PASS: {index} CLI fuzz cases in {elapsed:.1f}s, seed={args.seed}, reconnects={reconnects}")
        except BaseException as error:
            reproducer = write_reproducer(args.seed, history, error)
            print(f"FAIL: {error}; reproducer: {reproducer}")
            raise
        finally:
            if sock is not None:
                sock.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.stdout and not process.stdout.closed:
                output = process.stdout.read()
                if output:
                    print("--- smithproxy output ---")
                    print(output[-8000:])
                    sanitizer_markers = ("ERROR: AddressSanitizer", "runtime error:")
                    if any(marker in output for marker in sanitizer_markers):
                        reproducer = write_reproducer(
                            args.seed, history, RuntimeError("sanitizer reported a memory error")
                        )
                        raise RuntimeError(f"sanitizer reported a memory error; reproducer: {reproducer}")


if __name__ == "__main__":
    main()
