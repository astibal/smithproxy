#!/usr/bin/env python3

import argparse
import concurrent.futures
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

import http_connect_integration as integration


def concurrent_tunnel(listener_port, sequence):
    origin = integration.EchoOrigin()
    origin.start()
    authority = f"127.0.0.1:{origin.port}"
    with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
        client.settimeout(15)
        request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"X-Sequence: {sequence}\r\n\r\n"
        ).encode()
        # Exercise arbitrary packet boundaries, including byte-at-a-time input.
        stride = sequence % 11 + 1
        for offset in range(0, len(request), stride):
            client.sendall(request[offset:offset + stride])
            if stride == 1:
                time.sleep(0.001)
        response = integration.recv_until(client, b"\r\n\r\n")
        if not response.startswith(b"HTTP/1.1 200 Connection Established\r\n"):
            raise RuntimeError(f"concurrent CONNECT #{sequence} failed: {response!r}")
        client.sendall(b"PING\r\n")
        if integration.recv_until(client, b"PONG\r\n") != b"PONG\r\n":
            raise RuntimeError(f"concurrent tunnel #{sequence} payload mismatch")
    if not origin.finished.wait(5):
        raise RuntimeError(f"concurrent origin #{sequence} did not finish")
    if origin.error:
        raise origin.error


def malformed_corpus(listener_port):
    requests = (
        b"\r\n\r\n",
        b"CONNECT\r\n\r\n",
        b"connect example.test:443 HTTP/1.1\r\n\r\n",
        b"CONNECT :443 HTTP/1.1\r\n\r\n",
        b"CONNECT example.test:0 HTTP/1.1\r\n\r\n",
        b"CONNECT example.test:65536 HTTP/1.1\r\n\r\n",
        b"CONNECT [::1:443 HTTP/1.1\r\n\r\n",
        b"CONNECT ::1:443 HTTP/1.1\r\n\r\n",
        b"GET example.test:443 HTTP/1.1\r\n\r\n",
    )
    for request in requests:
        with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
            client.settimeout(10)
            client.sendall(request)
            response = integration.recv_until(client, b"\r\n\r\n")
            if not response.startswith(b"HTTP/1.1 400 Bad Request\r\n"):
                raise RuntimeError(f"malformed request was not rejected: {request!r}: {response!r}")


def unavailable_churn(listener_port, count):
    for _ in range(count):
        port = integration.free_port()
        with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
            client.settimeout(10)
            client.sendall((
                f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n\r\n").encode())
            response = integration.recv_until(client, b"\r\n\r\n")
            if not response.startswith(b"HTTP/1.1 502 Bad Gateway\r\n"):
                raise RuntimeError(f"unavailable upstream returned: {response!r}")


def pipeline_probe(listener_port):
    origin = integration.EchoOrigin()
    origin.start()
    authority = f"127.0.0.1:{origin.port}"
    with socket.create_connection(("127.0.0.1", listener_port), timeout=10) as client:
        client.settimeout(15)
        client.sendall((
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n\r\n").encode() + b"PING\r\n")
        response = integration.recv_until(client, b"\r\n\r\n")
        if not response.startswith(b"HTTP/1.1 200 Connection Established\r\n"):
            raise RuntimeError(f"pipelined CONNECT failed: {response!r}")
        client.settimeout(1)
        try:
            payload = integration.recv_until(client, b"PONG\r\n")
            if payload != b"PONG\r\n":
                raise RuntimeError(f"pipelined response mismatch: {payload!r}")
            result = "preserved"
        except TimeoutError:
            result = "dropped"
            client.settimeout(15)
            client.sendall(b"PING\r\n")
            if integration.recv_until(client, b"PONG\r\n") != b"PONG\r\n":
                raise RuntimeError("tunnel did not recover after dropped pipelined payload")
    if not origin.finished.wait(5):
        raise RuntimeError("pipelining origin did not finish")
    if origin.error:
        raise origin.error
    return result


def run(args):
    executable = args.smithproxy.resolve()
    worktree = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-http-connect-stress-") as temp:
        runtime = pathlib.Path(temp)
        config = runtime / "smithproxy.cfg"
        listener_port = integration.free_port()
        integration.make_config(
            worktree / "etc/smithproxy.cfg", config, worktree, runtime,
            listener_port, integration.free_port())
        process = subprocess.Popen(
            [str(executable), "--config-file", str(config), "--debug"],
            cwd=worktree, env=integration.process_env(runtime),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            integration.wait_for_listener(process, listener_port)
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                futures = [
                    pool.submit(concurrent_tunnel, listener_port, sequence)
                    for sequence in range(args.connections)
                ]
                for future in futures:
                    future.result()
            malformed_corpus(listener_port)
            unavailable_churn(listener_port, args.failures)
            pipeline = pipeline_probe(listener_port)
        finally:
            process.terminate()
            try:
                # Allow the proxy to drain worker/logging threads.  A forced
                # SIGKILL loses sanitizer diagnostics and gcov counters.
                output, _ = process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            if sys.exc_info()[0] is not None:
                print(output, file=sys.stderr)
                for log_file in runtime.glob("messages.*.log"):
                    print(log_file.read_text(errors="replace"), file=sys.stderr)

    print(
        f"HTTP CONNECT stress: PASS ({args.connections} tunnels, "
        f"{args.failures} upstream failures, pipelined payload {pipeline})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smithproxy", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument("--connections", type=int, default=64)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--failures", type=int, default=32)
    run(parser.parse_args())
