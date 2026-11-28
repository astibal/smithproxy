#!/usr/bin/env python3

"""Verify that --no-api suppresses HTTP without disabling local admin auth."""

import argparse
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile

TLS_HELPERS = pathlib.Path(__file__).resolve().parents[1] / "tls"
sys.path.insert(0, str(TLS_HELPERS))
from starttls_socks_integration import free_port, make_config

CLI_HELPERS = pathlib.Path(__file__).resolve().parents[1] / "cli"
sys.path.insert(0, str(CLI_HELPERS))
from libcli2_process_e2e import wait_for_port


def run(args):
    executable = args.smithproxy.resolve()
    source = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-no-api-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        socks_port = free_port()
        cli_port = free_port()
        api_port = free_port()
        make_config(
            source / "etc/smithproxy.cfg",
            config,
            source,
            runtime,
            socks_port,
            cli_port,
        )

        text = config.read_text().replace(
            "accept_api = FALSE;",
            f"accept_api = TRUE;\n    http_api = {{ port = {api_port}; }};",
            1,
        )
        config.write_text(text)

        runtime_key = runtime / "gui-api.key"
        auth_socket = runtime / "admin-auth.sock"
        process = subprocess.Popen(
            [str(executable), "--config-file", str(config), "--no-api",
             "--cli-socket", str(runtime / "cli.sock")],
            cwd=source,
            env={
                **os.environ,
                "SMITHPROXY_PID_FILE": str(runtime / "smithproxy.pid"),
                "SMITHPROXY_ADMIN_API_KEY_FILE": str(runtime_key),
                "SMITHPROXY_ADMIN_AUTH_SOCKET": str(auth_socket),
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        output = ""
        try:
            wait_for_port(process, cli_port)
            with socket.socket() as connection:
                connection.settimeout(0.5)
                assert connection.connect_ex(("127.0.0.1", api_port)) != 0

            assert not runtime_key.exists()
            assert stat.S_ISSOCK(auth_socket.stat().st_mode)
            print("HTTP API --no-api boundary: PASS")
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, default=pathlib.Path.cwd())
    run(parser.parse_args())


if __name__ == "__main__":
    main()
