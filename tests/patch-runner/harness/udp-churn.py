#!/usr/bin/env python3
"""Exercise UDP flow creation and expiry while a continuous probe stays active."""

import argparse
import concurrent.futures
import socket
import threading
import time


def exchange(family: int, target: tuple, expected_peer: bytes,
             source_port: int, payload: bytes, timeout: float) -> None:
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", source_port))
        sock.settimeout(timeout)
        sock.sendto(payload, target)
        reply, peer = sock.recvfrom(65535)
        expected = payload + expected_peer
        if peer[0:2] != target or not reply.startswith(expected):
            raise RuntimeError(
                f"port={source_port} peer={peer!r} reply={reply!r} expected_prefix={expected!r}"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--waves", type=int, default=8)
    parser.add_argument("--flows", type=int, default=96)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--settle", type=float, default=12.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--min-port", type=int, default=20000)
    parser.add_argument("--max-port", type=int, default=29999)
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--expected-peer", default="198.18.20.1")
    args = parser.parse_args()
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    target = (args.host, 9999)
    expected_peer = f" peer={args.expected_peer} sport=".encode()

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
        while not stop.is_set():
            try:
                exchange(family, target, expected_peer, 19000, f"probe-{sequence}".encode(), args.timeout)
                probe_count += 1
            except Exception as exc:  # keep probing so one stall does not hide later ones
                probe_errors.append(str(exc))
            sequence += 1
            stop.wait(0.02)

    probe_thread = threading.Thread(target=probe, name="udp-continuous-probe")
    probe_thread.start()

    churn_errors: list[str] = []
    started = time.monotonic()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            for wave in range(args.waves):
                futures = []
                for index in range(args.flows):
                    source_port = args.min_port + wave * args.flows + index
                    payload = f"churn-{wave}-{index}".encode()
                    futures.append(pool.submit(exchange, family, target, expected_peer,
                                               source_port, payload, args.timeout))

                for future in futures:
                    try:
                        future.result()
                    except Exception as exc:
                        churn_errors.append(str(exc))

                time.sleep(args.interval)

            # Keep the probe running across expiry and deferred reaping of the
            # final waves as well.
            time.sleep(args.settle)
    finally:
        stop.set()
        probe_thread.join()

    elapsed = time.monotonic() - started
    print(
        f"UDP churn: family=IPv{6 if family == socket.AF_INET6 else 4} flows={total} probes={probe_count} elapsed={elapsed:.2f}s "
        f"churn_errors={len(churn_errors)} probe_errors={len(probe_errors)}"
    )

    if churn_errors or probe_errors:
        for error in (churn_errors + probe_errors)[:20]:
            print(f"ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
