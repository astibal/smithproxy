#!/usr/bin/env python3
"""End-to-end password/exec test through Smithproxy's SOCKS listener."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

import paramiko


USER = "smithproxy-e2e"
PASSWORD = "password-e2e"
COMMANDS = (b"printf smithproxy-ssh-e2e-1", b"printf smithproxy-ssh-e2e-2")
REPLIES = (b"smithproxy-ssh-e2e-1\n", b"smithproxy-ssh-e2e-2\n")
FORWARD_PAYLOAD = b"ssh-direct-tcpip-e2e"
REMOTE_FORWARD_PAYLOAD = b"ssh-forwarded-tcpip-e2e"
REMOTE_FORWARD_REPLY = b"ssh-forwarded-tcpip-reply"
X11_PAYLOAD = b"ssh-x11-e2e"
X11_REPLY = b"ssh-x11-reply"
AGENT_PAYLOAD = b"ssh-agent-e2e"
AGENT_REPLY = b"ssh-agent-reply"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def replace_setting(text: str, name: str, value: str) -> str:
    pattern = rf"(?m)^(\s*{re.escape(name)}\s*=\s*).*$"
    result, count = re.subn(pattern, rf"\g<1>{value}", text, count=1)
    if count != 1:
        raise AssertionError(f"setting not found: {name}")
    return result


class TestServer(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.commands: list[bytes] = []
        self.direct_destinations: dict[int, tuple[str, int]] = {}
        self.remote_forward: tuple[str, int] | None = None
        self.remote_forward_ready = threading.Event()
        self.remote_forward_cancelled = threading.Event()
        self.x11_requested = threading.Event()
        self.agent_requested = threading.Event()

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        return (paramiko.AUTH_SUCCESSFUL
                if username == USER and password == PASSWORD
                else paramiko.AUTH_FAILED)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return (paramiko.OPEN_SUCCEEDED
                if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.commands.append(command)
        index = len(self.commands) - 1
        reply = REPLIES[index] if index < len(REPLIES) else b"unexpected-command\n"

        def answer() -> None:
            # Return the request-success packet before an intentionally tiny
            # command finishes and closes its channel.
            time.sleep(0.2)
            channel.sendall(reply)
            channel.send_exit_status(0)
            channel.shutdown_write()
            channel.close()

        threading.Thread(target=answer, daemon=True).start()
        return True

    def check_channel_direct_tcpip_request(
            self, chanid: int, origin: tuple[str, int], destination: tuple[str, int]) -> int:
        self.direct_destinations[chanid] = destination
        return paramiko.OPEN_SUCCEEDED

    def check_port_forward_request(self, address: str, port: int) -> int:
        self.remote_forward = (address, port or 40000)
        self.remote_forward_ready.set()
        return self.remote_forward[1]

    def cancel_port_forward_request(self, address: str, port: int) -> None:
        self.remote_forward_cancelled.set()

    def check_channel_x11_request(self, channel: paramiko.Channel,
                                  single_connection: bool, auth_protocol: str,
                                  auth_cookie: str, screen_number: int) -> bool:
        self.x11_requested.set()
        return True

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        self.agent_requested.set()
        return True


def relay_direct(channel: paramiko.Channel, destination: tuple[str, int]) -> None:
    with socket.create_connection(destination, timeout=10) as target:
        data = channel.recv(65536)
        target.sendall(data)
        channel.sendall(target.recv(65536))
    channel.close()


def run_server(listener: socket.socket, host_key: paramiko.PKey,
               ready: threading.Event, errors: list[BaseException],
               expect_direct: bool, expect_remote: bool,
               expect_x11: bool, expect_agent: bool,
               feature_requests_done: threading.Event) -> None:
    try:
        ready.set()
        connection, _ = listener.accept()
        print("e2e server: TCP accepted", flush=True)
        with connection:
            transport = paramiko.Transport(connection)
            transport.add_server_key(host_key)
            server = TestServer()
            transport.start_server(server=server)
            print("e2e server: SSH transport started", flush=True)
            direct_threads: list[threading.Thread] = []
            for _ in range(5 if expect_direct else 4):
                channel = transport.accept(15)
                if channel is None:
                    raise AssertionError("test SSH server did not receive all channels")
                destination = server.direct_destinations.get(channel.get_id())
                if destination:
                    thread = threading.Thread(
                        target=relay_direct, args=(channel, destination), daemon=True)
                    thread.start()
                    direct_threads.append(thread)
            for thread in direct_threads:
                thread.join(15)
                if thread.is_alive():
                    raise AssertionError("direct-tcpip relay did not finish")
            if expect_remote:
                if not server.remote_forward_ready.wait(15) or not server.remote_forward:
                    raise AssertionError("test SSH server did not receive remote forwarding request")
                remote = transport.open_forwarded_tcpip_channel(
                    server.remote_forward, ("198.51.100.23", 54321))
                remote.sendall(REMOTE_FORWARD_PAYLOAD)
                if remote.recv(len(REMOTE_FORWARD_REPLY)) != REMOTE_FORWARD_REPLY:
                    raise AssertionError("unexpected remote-forward response")
                remote.close()
                if not server.remote_forward_cancelled.wait(15):
                    raise AssertionError("test SSH server did not receive forwarding cancellation")
            if not feature_requests_done.wait(15):
                raise AssertionError("client did not finish feature requests")
            if expect_x11:
                if not server.x11_requested.wait(15):
                    raise AssertionError("test SSH server did not receive X11 request")
                x11 = transport.open_x11_channel(("203.0.113.11", 6010))
                x11.sendall(X11_PAYLOAD)
                if x11.recv(len(X11_REPLY)) != X11_REPLY:
                    raise AssertionError("unexpected X11 response")
                x11.close()
            elif server.x11_requested.wait(0.5):
                raise AssertionError("x11=reject reached the upstream server")
            if expect_agent:
                if not server.agent_requested.wait(15):
                    raise AssertionError("test SSH server did not receive agent request")
                agent = transport.open_forward_agent_channel()
                agent.sendall(AGENT_PAYLOAD)
                if agent.recv(len(AGENT_REPLY)) != AGENT_REPLY:
                    raise AssertionError("unexpected agent response")
                agent.close()
            elif server.agent_requested.wait(0.5):
                raise AssertionError("agent=reject reached the upstream server")
            command_deadline = time.monotonic() + 15
            while len(server.commands) < len(COMMANDS) \
                    and time.monotonic() < command_deadline:
                time.sleep(0.01)
            if server.commands != list(COMMANDS):
                raise AssertionError(f"unexpected commands: {server.commands!r}")
            deadline = time.monotonic() + 15
            while transport.is_active() and time.monotonic() < deadline:
                time.sleep(0.05)
            transport.close()
    except BaseException as error:  # reported by the main test thread
        errors.append(error)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise AssertionError("SOCKS proxy closed unexpectedly")
        result.extend(chunk)
    return bytes(result)


def socks_connect(port: int, target_port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise AssertionError("SOCKS method negotiation failed")
    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                 + struct.pack("!H", target_port))
    response = recv_exact(sock, 4)
    if response[1] != 0:
        raise AssertionError(f"SOCKS connect failed: {response!r}")
    address_size = 4 if response[3] == 1 else 16
    recv_exact(sock, address_size + 2)
    sock.settimeout(15)
    return sock


def run_echo_server(listener: socket.socket, errors: list[BaseException]) -> None:
    try:
        connection, _ = listener.accept()
        with connection:
            data = connection.recv(65536)
            connection.sendall(data)
    except BaseException as error:
        errors.append(error)


def wait_for_port(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            raise AssertionError(f"Smithproxy exited early ({process.returncode}):\n{output}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("Smithproxy SOCKS port did not open")


def enable_ssh_debug(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as cli:
        cli.settimeout(0.2)
        time.sleep(0.1)
        try:
            cli.recv(65536)
        except TimeoutError:
            pass
        for command in ("enable", "debug proxy 8",
                        "debug set com.ssh 8",
                        "debug set com.ssh.shell 8", "debug set com.ssh.exec 8",
                        "show config ssh_profiles", "diag proxy policy list"):
            cli.sendall(command.encode() + b"\r\n")
            time.sleep(0.1)
            try:
                response = cli.recv(65536)
            except TimeoutError:
                response = b""
            if command.startswith("debug set") and b"debug level:" not in response:
                raise AssertionError(f"CLI failed to enable {command!r}: {response!r}")
            if command.startswith("show ") or command.startswith("diag "):
                print(f"--- {command} ---\n{response.decode('utf-8', 'replace')}", flush=True)


def print_session_list(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as cli:
        cli.settimeout(0.3)
        time.sleep(0.1)
        try:
            cli.recv(65536)
        except TimeoutError:
            pass
        cli.sendall(b"enable\r\n")
        time.sleep(0.1)
        try:
            cli.recv(65536)
        except TimeoutError:
            pass
        cli.sendall(b"diag proxy session list 8\r\n")
        time.sleep(0.3)
        try:
            response = cli.recv(65536)
        except TimeoutError:
            response = b""
        print(f"--- session list ---\n{response.decode('utf-8', 'replace')}", flush=True)


def assert_capture_annotations(capture_dir: Path, expected: tuple[bytes, ...]) -> None:
    deadline = time.monotonic() + 5
    capture = b""
    while time.monotonic() < deadline:
        capture_files = [path for path in capture_dir.rglob("*")
                         if path.is_file() and path.suffix in (".pcap", ".pcapng")]
        capture = b"".join(path.read_bytes() for path in capture_files)
        if all(marker in capture for marker in expected):
            return
        time.sleep(0.1)
    missing = [marker.decode() for marker in expected if marker not in capture]
    raise AssertionError(
        f"missing PCAPNG annotations: {missing}; files={capture_files}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--reject-local-forward", action="store_true")
    parser.add_argument("--reject-remote-forward", action="store_true")
    parser.add_argument("--reject-x11", action="store_true")
    parser.add_argument("--reject-agent", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()

    with tempfile.TemporaryDirectory(prefix="smithproxy-ssh-e2e-") as tmp_name:
        tmp = Path(tmp_name)
        (tmp / "capture").mkdir()
        mitm_key = tmp / "mitm_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(mitm_key)], check=True)
        server_key = paramiko.Ed25519Key.from_private_key_file(str(mitm_key))

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        server_port = int(listener.getsockname()[1])
        echo_listener = socket.socket()
        echo_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo_listener.bind(("127.0.0.1", 0))
        echo_listener.listen(1)
        echo_port = int(echo_listener.getsockname()[1])
        socks_port = free_port()
        cli_port = free_port()

        config = tmp / "smithproxy.cfg"
        shutil.copyfile(source / "etc/smithproxy.cfg", config)
        text = config.read_text()
        for name, value in (
            ("accept_tproxy", "FALSE;"),
            ("accept_redirect", "FALSE;"),
            ("accept_socks", "TRUE;"),
            ("socks_workers", "1;"),
            ("certs_path", f'"{source / "etc/certs/default"}/";'),
            ("messages_dir", f'"{source / "etc/msg/en"}/";'),
            ("log_file", '"";'),
            ("log_console", "TRUE;"),
            ("sslkeylog_file", f'"{tmp}/sslkeylog.%s.log";'),
            ("write_payload_dir", f'"{tmp}/payload";'),
        ):
            text = replace_setting(text, name, value)
        text = text.replace(
            "settings = {",
            f'settings = {{\n    accept_api = FALSE;\n    socks_port = "{socks_port}";', 1)
        text = re.sub(r"(?m)^(\s*port\s*=\s*)50000;", rf"\g<1>{cli_port};", text, count=1)
        text = re.sub(
            r"ssh_profiles\s*=\s*\{\s*\}",
            f'ssh_profiles = {{ e2e = {{ host_key = "{mitm_key}"; '
            f'local_forward = "{"reject" if args.reject_local_forward else "pass"}"; '
            f'remote_forward = "{"reject" if args.reject_remote_forward else "pass"}"; '
            f'x11 = "{"reject" if args.reject_x11 else "pass"}"; '
            f'agent = "{"reject" if args.reject_agent else "pass"}"; }} }}',
            text, count=1)
        text = text.replace(
            "content_profiles = {",
            "content_profiles = {\n"
            "    ssh_e2e = { write_payload = TRUE; write_format = \"pcap_single\"; };",
            1)
        text = text.replace(
            'dir = "/var/smithproxy/data"', f'dir = "{tmp}/capture"', 1)
        policy = f'''policy = (
    {{
        proto = "tcp";
        src = [ "any", "any6" ];
        sport = [ "all" ];
        dst = [ "any", "any6" ];
        dport = [ "all" ];
        ssh_profile = "e2e";
        content_profile = "ssh_e2e";
        action = "accept";
        nat = "auto";
        routing = "none";
    }}
)

'''
        text, count = re.subn(r"policy\s*=\s*\(.*?\)\s*\n\n(?=starttls_signatures)",
                              policy, text, count=1, flags=re.DOTALL)
        if count != 1:
            raise AssertionError("cannot replace policy section")
        config.write_text(text)

        ready = threading.Event()
        feature_requests_done = threading.Event()
        server_errors: list[BaseException] = []
        server_thread = threading.Thread(
            target=run_server,
            args=(listener, server_key, ready, server_errors,
                  not args.reject_local_forward,
                  not args.reject_remote_forward,
                  not args.reject_x11,
                  not args.reject_agent,
                  feature_requests_done), daemon=True)
        server_thread.start()
        echo_thread = None
        if not args.reject_local_forward:
            echo_thread = threading.Thread(
                target=run_echo_server, args=(echo_listener, server_errors), daemon=True)
            echo_thread.start()
        ready.wait(5)

        env = os.environ.copy()
        env["SMITHPROXY_PID_FILE"] = str(tmp / "smithproxy.pid")
        process = subprocess.Popen(
            [str(args.binary.resolve()), "--config-file", str(config), "--debug"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            wait_for_port(process, cli_port)
            enable_ssh_debug(cli_port)
            client_socket = socks_connect(socks_port, server_port)
            client = paramiko.Transport(client_socket)
            client.start_client(timeout=15)
            client.auth_password(USER, PASSWORD)
            received: list[bytes] = []
            for command in COMMANDS:
                channel = client.open_session(timeout=15)
                channel.exec_command(command)
                output = bytearray()
                while True:
                    chunk = channel.recv(65536)
                    if not chunk:
                        break
                    output.extend(chunk)
                if channel.recv_exit_status() != 0:
                    raise AssertionError("exec channel returned a non-zero exit status")
                received.append(bytes(output))

            forwarded_reply = b""
            try:
                forwarded = client.open_channel(
                    "direct-tcpip", ("127.0.0.1", echo_port), ("127.0.0.1", 4242),
                    timeout=15)
            except paramiko.ChannelException:
                if not args.reject_local_forward:
                    raise
            else:
                if args.reject_local_forward:
                    raise AssertionError("local_forward=reject accepted direct-tcpip")
                forwarded.sendall(FORWARD_PAYLOAD)
                forwarded_reply = forwarded.recv(len(FORWARD_PAYLOAD))
                forwarded.shutdown_write()
                forwarded.close()

            x11_relay_done = threading.Event()
            agent_relay_done = threading.Event()

            def answer_feature(channel: paramiko.Channel, payload: bytes,
                               reply: bytes, done: threading.Event) -> None:
                try:
                    if channel.recv(len(payload)) != payload:
                        raise AssertionError("unexpected server-initiated feature payload")
                    channel.sendall(reply)
                    channel.close()
                except BaseException as error:
                    server_errors.append(error)
                finally:
                    done.set()

            def x11_handler(channel: paramiko.Channel, origin: tuple[str, int]) -> None:
                threading.Thread(target=answer_feature,
                    args=(channel, X11_PAYLOAD, X11_REPLY, x11_relay_done),
                    daemon=True).start()

            def agent_handler(channel: paramiko.Channel) -> None:
                threading.Thread(target=answer_feature,
                    args=(channel, AGENT_PAYLOAD, AGENT_REPLY, agent_relay_done),
                    daemon=True).start()

            x11_feature_channel = client.open_session(timeout=15)
            try:
                x11_feature_channel.request_x11(
                    auth_protocol="MIT-MAGIC-COOKIE-1",
                    auth_cookie="00112233445566778899aabbccddeeff",
                    handler=x11_handler)
            except paramiko.SSHException:
                if not args.reject_x11:
                    raise
            else:
                if args.reject_x11:
                    raise AssertionError("x11=reject accepted X11 request")
            agent_feature_channel = client.open_session(timeout=15)
            agent_feature_channel.request_forward_agent(agent_handler)
            feature_requests_done.set()

            try:
                remote_port = client.request_port_forward("127.0.0.1", 40000)
            except paramiko.SSHException:
                if not args.reject_remote_forward:
                    raise
            else:
                if args.reject_remote_forward:
                    raise AssertionError("remote_forward=reject accepted tcpip-forward")
                if remote_port != 40000:
                    raise AssertionError(f"unexpected remote forwarding port: {remote_port}")
                remote = client.accept(15)
                if remote is None:
                    raise AssertionError("client did not receive forwarded-tcpip channel")
                if remote.recv(len(REMOTE_FORWARD_PAYLOAD)) != REMOTE_FORWARD_PAYLOAD:
                    raise AssertionError("unexpected remote-forward payload")
                remote.sendall(REMOTE_FORWARD_REPLY)
                remote.close()
                client.cancel_port_forward("127.0.0.1", remote_port)
            if not args.reject_x11 and not x11_relay_done.wait(15):
                raise AssertionError("client did not receive X11 channel")
            if not args.reject_agent and not agent_relay_done.wait(15):
                raise AssertionError("client did not receive agent channel")
            if args.reject_x11 and x11_relay_done.wait(0.5):
                raise AssertionError("x11=reject relayed an X11 channel")
            if args.reject_agent and agent_relay_done.wait(0.5):
                raise AssertionError("agent=reject relayed an agent channel")
            x11_feature_channel.close()
            agent_feature_channel.close()
            time.sleep(1)
            print_session_list(cli_port)
            client.close()
            client_socket.close()
            server_thread.join(15)
            if echo_thread:
                echo_thread.join(15)
            if server_errors:
                raise server_errors[0]
            if received != list(REPLIES):
                raise AssertionError(f"unexpected SSH output: {received!r}")
            if not args.reject_local_forward and forwarded_reply != FORWARD_PAYLOAD:
                raise AssertionError(f"unexpected forwarded output: {forwarded_reply!r}")
            if server_thread.is_alive():
                raise AssertionError("test SSH server did not finish")
            if echo_thread and echo_thread.is_alive():
                raise AssertionError("echo server did not finish")
            process.terminate()
            process.wait(timeout=25)
            annotations = [b"ssh event=channel-open", b"ssh event=exec",
                           b"ssh event=relay"]
            if args.reject_remote_forward:
                annotations.append(b"ssh event=remote-forward action=reject")
            else:
                annotations.append(b"ssh event=remote-forward action=listen")
                annotations.append(b"type=forwarded-tcpip")
            if args.reject_local_forward:
                annotations.append(b"type=direct-tcpip action=reject")
            if args.reject_x11:
                annotations.append(b"ssh event=channel-request subtype=7 action=reject")
            else:
                annotations.append(b"ssh event=channel-open type=x11 action=pass")
            if args.reject_agent:
                annotations.append(b"ssh event=channel-request type=auth-agent action=reject")
            else:
                annotations.append(b"ssh event=channel-open type=auth-agent action=pass")
            assert_capture_annotations(tmp, tuple(annotations))
            if args.reject_x11:
                print("PASS: x11=reject blocked X11 while agent forwarding passed")
            elif args.reject_agent:
                print("PASS: agent=reject blocked agent while X11 forwarding passed")
            elif args.reject_remote_forward:
                print("PASS: remote_forward=reject blocked tcpip-forward without breaking exec")
            elif args.reject_local_forward:
                print("PASS: local_forward=reject blocked direct-tcpip; remote forward passed")
            else:
                print("PASS: exec, TCP, X11 and agent channels traversed one SSH MITM transport")
        except BaseException:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            print("--- smithproxy output ---")
            print(output)
            raise
        finally:
            listener.close()
            echo_listener.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    main()
