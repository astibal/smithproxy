#!/usr/bin/env python3
"""Exercise TCP proxy creation/destruction while a persistent flow stays active."""

import argparse
import concurrent.futures
import socket
import threading
import time


TARGET = ("198.18.20.2", 9998)


def receive_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError(f"short TCP echo: {len(chunks)}/{size}")
        chunks.extend(chunk)
    return bytes(chunks)


def exchange(source_port: int, payload: bytes, timeout: float) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", source_port))
        sock.settimeout(timeout)
        sock.connect(TARGET)
        sock.sendall(payload)
        reply = receive_exact(sock, len(payload))
        if reply != payload:
            raise RuntimeError(f"port={source_port} reply={reply!r} expected={payload!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--waves", type=int, default=20)
    parser.add_argument("--flows", type=int, default=64)
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("--settle", type=float, default=15.0)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--min-port", type=int, default=20000)
    parser.add_argument("--max-port", type=int, default=29999)
    args = parser.parse_args()

    total = args.waves * args.flows
    if not 1 <= args.min_port <= args.max_port <= 65535:
        parser.error("port range must satisfy 1 <= MIN <= MAX <= 65535")
    if total > args.max_port - args.min_port + 1:
        parser.error(f"port range has fewer than {total} ports")

    stop = threading.Event()
    probe_errors: list[str] = []
    probe_count = 0

    def probe() -> None:
        nonlocal probe_count
        sequence = 0
        try:
            with socket.create_connection(TARGET, timeout=args.timeout) as sock:
                sock.settimeout(args.timeout)
                while not stop.is_set():
                    payload = f"persistent-{sequence:08d}\n".encode()
                    sock.sendall(payload)
                    reply = receive_exact(sock, len(payload))
                    if reply != payload:
                        raise RuntimeError(f"persistent reply={reply!r} expected={payload!r}")
                    probe_count += 1
                    sequence += 1
                    stop.wait(0.02)
        except Exception as exc:
            probe_errors.append(str(exc))

    probe_thread = threading.Thread(target=probe, name="tcp-persistent-probe")
    probe_thread.start()

    churn_errors: list[str] = []
    started = time.monotonic()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            for wave in range(args.waves):
                futures = []
                for index in range(args.flows):
                    source_port = args.min_port + wave * args.flows + index
                    payload = f"tcp-churn-{wave}-{index}\n".encode()
                    futures.append(pool.submit(exchange, source_port, payload, args.timeout))
                for future in futures:
                    try:
                        future.result()
                    except Exception as exc:
                        churn_errors.append(str(exc))
                time.sleep(args.interval)
        time.sleep(args.settle)
    finally:
        stop.set()
        probe_thread.join()

    elapsed = time.monotonic() - started
    print(
        f"TCP churn: flows={total} probes={probe_count} elapsed={elapsed:.2f}s "
        f"churn_errors={len(churn_errors)} probe_errors={len(probe_errors)}"
    )
    if churn_errors or probe_errors:
        for error in (churn_errors + probe_errors)[:20]:
            print(f"ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
