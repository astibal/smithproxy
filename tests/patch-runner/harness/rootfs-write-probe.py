#!/usr/bin/env python3
"""Ask a running Smithproxy to persist its config through the rootfs bind mount."""

import re
import socket
import sys


TELNET = re.compile(rb"\xff[\xfb-\xfe].")


def read_prompt(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while not TELNET.sub(b"", data).endswith(marker):
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("Smithproxy closed the CLI before the prompt")
        data.extend(chunk)
    return TELNET.sub(b"", data)


def main() -> int:
    sock = socket.create_connection(("127.0.0.1", 50000), timeout=5)
    sock.settimeout(5)
    try:
        read_prompt(sock, b")> ")
        sock.sendall(b"enable\r\n")
        read_prompt(sock, b")# ")
        sock.sendall(b"save config\r\n")
        output = read_prompt(sock, b")# ")
        sys.stdout.buffer.write(output)
        if b"config saved successfully" not in output:
            raise RuntimeError("Smithproxy did not confirm a successful config save")
        sock.sendall(b"quit\r\n")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
