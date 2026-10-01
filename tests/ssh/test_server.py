#!/usr/bin/env python3
"""Small password-auth SSH server for manual Smithproxy MITM testing.

The server never executes received commands on the host. Exec requests are
printed and returned as text; an interactive shell supports help, whoami,
echo and exit.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import threading

import paramiko


class Server(paramiko.ServerInterface):
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.event = threading.Event()
        self.request = ""
        self.command = b""

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        print(f"auth user={username!r}", flush=True)
        return (paramiko.AUTH_SUCCESSFUL
                if username == self.username and password == self.password
                else paramiko.AUTH_FAILED)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        print(f"channel kind={kind!r} id={chanid}", flush=True)
        return (paramiko.OPEN_SUCCEEDED
                if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_pty_request(self, channel: paramiko.Channel, term: bytes,
                                  width: int, height: int, pixelwidth: int,
                                  pixelheight: int, modes: bytes) -> bool:
        print(f"pty term={term!r} size={width}x{height}", flush=True)
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.request = "shell"
        self.event.set()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.request = "exec"
        self.command = command
        self.event.set()
        return True

    def check_channel_subsystem_request(self, channel: paramiko.Channel, name: str) -> bool:
        self.request = f"subsystem:{name}"
        self.event.set()
        return True


def load_host_key(path: Path | None) -> paramiko.PKey:
    if path is None:
        print("using ephemeral RSA host key", flush=True)
        return paramiko.RSAKey.generate(2048)
    for key_type in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return key_type.from_private_key_file(str(path))
        except (paramiko.SSHException, ValueError):
            continue
    raise ValueError(f"cannot load SSH host key: {path}")


def interactive_shell(channel: paramiko.Channel, username: str) -> None:
    channel.sendall(b"Smithproxy SSH MITM test server\r\n")
    channel.sendall(b"Commands: help, whoami, echo TEXT, exit\r\n")
    pending = bytearray()
    while True:
        channel.sendall(b"test-ssh> ")
        while b"\n" not in pending:
            data = channel.recv(4096)
            if not data:
                return
            pending.extend(data)
        line, _, rest = pending.partition(b"\n")
        pending = bytearray(rest)
        command = line.rstrip(b"\r").decode("utf-8", "replace")
        print(f"shell command={command!r}", flush=True)
        if command == "exit":
            channel.sendall(b"bye\r\n")
            return
        if command in ("help", "?"):
            channel.sendall(b"help | whoami | echo TEXT | exit\r\n")
        elif command == "whoami":
            channel.sendall(username.encode() + b"\r\n")
        elif command.startswith("echo "):
            channel.sendall(command[5:].encode() + b"\r\n")
        elif command:
            channel.sendall(b"fake server: command not executed\r\n")


def serve_connection(connection: socket.socket, host_key: paramiko.PKey,
                     username: str, password: str) -> None:
    transport = paramiko.Transport(connection)
    transport.add_server_key(host_key)
    server = Server(username, password)
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            print("client did not open a channel", flush=True)
            return
        if not server.event.wait(20):
            print("client did not request shell/exec/subsystem", flush=True)
            return
        if server.request == "shell":
            interactive_shell(channel, username)
            channel.send_exit_status(0)
        elif server.request == "exec":
            command = server.command.decode("utf-8", "replace")
            print(f"exec command={command!r}", flush=True)
            channel.sendall(f"fake exec: {command}\n".encode())
            channel.send_exit_status(0)
        else:
            print(f"request={server.request!r}", flush=True)
            channel.sendall(f"fake {server.request}\n".encode())
            channel.send_exit_status(0)
        channel.shutdown_write()
        channel.close()
    finally:
        transport.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe fake SSH server for Smithproxy MITM testing"
    )
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="smithproxy")
    parser.add_argument("--password", default="smithproxy")
    parser.add_argument("--host-key", type=Path)
    parser.add_argument("--once", action="store_true", help="exit after one connection")
    args = parser.parse_args()

    host_key = load_host_key(args.host_key)
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, args.port))
        listener.listen(16)
        print(f"listening on {args.bind}:{args.port}", flush=True)
        print(f"credentials: {args.user} / {args.password}", flush=True)
        while True:
            connection, peer = listener.accept()
            print(f"accepted {peer[0]}:{peer[1]}", flush=True)
            try:
                serve_connection(connection, host_key, args.user, args.password)
            except Exception as error:
                print(f"connection failed: {error}", flush=True)
            finally:
                connection.close()
            if args.once:
                break


if __name__ == "__main__":
    main()
