#!/usr/bin/env python3

"""Verify that --no-gui removes every GUI authentication entrance."""

import argparse
import http.client
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

from http_api_integration import api_request, wait_for_api

TLS_HELPERS = pathlib.Path(__file__).resolve().parents[1] / "tls"
sys.path.insert(0, str(TLS_HELPERS))
from starttls_socks_integration import free_port, make_config


def run(args):
    executable = args.smithproxy.resolve()
    source = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-no-gui-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        api_port = free_port()
        api_key = "smithproxy-no-gui-api-key"
        make_config(
            source / "etc/smithproxy.cfg",
            config,
            source,
            runtime,
            free_port(),
            free_port(),
        )

        text = config.read_text()
        api_settings = f'''accept_api = TRUE;
    http_api = {{
        keys = [ "{api_key}" ];
        loopback_only = TRUE;
        allow_api_header = TRUE;
        port = {api_port};
        pam_login = FALSE;
    }};'''
        text = text.replace("accept_api = FALSE;", api_settings, 1)
        config.write_text(text)

        runtime_key = runtime / "gui-api.key"
        auth_socket = runtime / "admin-auth.sock"
        process = subprocess.Popen(
            [str(executable), "--config-file", str(config), "--no-gui",
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
            wait_for_api(process, api_port)

            status, _, payload = api_request(
                api_port,
                "GET",
                "/api/config/state",
                headers={"X-API-Key": api_key},
            )
            assert status == 200, (status, payload)

            absent_routes = (
                ("POST", "/api/authorize"),
                ("POST", "/api/login"),
                ("POST", "/api/logout"),
                ("GET", "/api/session"),
                ("GET", "/api/admin/administrators"),
                ("POST", "/api/admin/enrollment/consume"),
            )
            for method, path in absent_routes:
                try:
                    status, _, _ = api_request(
                        api_port,
                        method,
                        path,
                        body="{}" if method == "POST" else None,
                        headers={"Content-Type": "application/json"},
                    )
                    assert status == 404, (method, path, status)
                except http.client.RemoteDisconnected:
                    # Some libmicrohttpd versions close an unregistered POST
                    # route instead of synthesizing a 404. Both outcomes prove
                    # that the GUI-only operation is not exposed.
                    pass

            assert not runtime_key.exists()
            assert stat.S_ISSOCK(auth_socket.stat().st_mode)
            print("HTTP API --no-gui boundary: PASS")
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
