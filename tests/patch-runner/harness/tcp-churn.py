#!/usr/bin/env python3
"""Exercise TCP proxy creation/destruction while a persistent flow stays active."""

import argparse
import concurrent.futures
import json
import socket
import struct
import threading
import time


def receive_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError(f"short TCP echo: {len(chunks)}/{size}")
        chunks.extend(chunk)
    return bytes(chunks)


def exchange(
    family: int,
    target: tuple,
    source_port: int,
    payload: bytes,
    timeout: float,
    start_barrier: threading.Barrier | None = None,
) -> None:
    if start_barrier is not None:
        start_barrier.wait()
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", source_port))
        sock.settimeout(timeout)
        sock.connect(target)
        sock.sendall(payload)
        reply = receive_exact(sock, len(payload))
        if reply != payload:
            raise RuntimeError(f"port={source_port} reply={reply!r} expected={payload!r}")


def endpoint(value: tuple) -> str:
    """Format IPv4 and IPv6 socket endpoints without losing the port."""
    host, port = value[:2]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def tcp_info(sock: socket.socket) -> dict:
    """Return the stable leading Linux TCP_INFO fields plus the complete blob."""
    raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
    result = {"raw_hex": raw.hex()}
    if len(raw) < 104:
        return result

    header = struct.unpack_from("=8B24I", raw)
    result.update(
        state=header[0],
        retransmits=header[2],
        probes=header[3],
        backoff=header[4],
        rto_us=header[8],
        unacked=header[12],
        sacked=header[13],
        lost=header[14],
        retrans=header[15],
        last_data_sent_ms=header[17],
        last_data_recv_ms=header[19],
        last_ack_recv_ms=header[20],
        rtt_us=header[23],
        rttvar_us=header[24],
        snd_cwnd=header[26],
        total_retrans=header[31],
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--waves", type=int, default=20)
    parser.add_argument("--flows", type=int, default=64)
    parser.add_argument("--parallel", type=int, default=64)
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("--settle", type=float, default=15.0)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--min-port", type=int, default=20000)
    parser.add_argument("--max-port", type=int, default=29999)
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--port", type=int, default=9998)
    parser.add_argument("--control-host")
    parser.add_argument("--control-port", type=int, default=9998)
    parser.add_argument("--event-log")
    parser.add_argument("--failure-hold", type=float, default=0.0)
    parser.add_argument(
        "--synchronized-start",
        action="store_true",
        help="release every connection in a wave from one barrier",
    )
    args = parser.parse_args()
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    target = (args.host, args.port)

    total = args.waves * args.flows
    if not 1 <= args.min_port <= args.max_port <= 65535:
        parser.error("port range must satisfy 1 <= MIN <= MAX <= 65535")
    if total > args.max_port - args.min_port + 1:
        parser.error(f"port range has fewer than {total} ports")
    if args.parallel < 1:
        parser.error("parallel must be at least one")
    if args.synchronized_start and args.parallel < args.flows:
        parser.error("synchronized start requires parallel >= flows")

    if not 1 <= args.port <= 65535 or not 1 <= args.control_port <= 65535:
        parser.error("target ports must be in range 1..65535")
    if args.failure_hold < 0:
        parser.error("failure hold must not be negative")

    stop = threading.Event()
    output_lock = threading.Lock()
    event_file = open(args.event_log, "a", buffering=1) if args.event_log else None
    probe_errors: dict[str, list[str]] = {"proxy": [], "control": []}
    probe_counts: dict[str, int] = {"proxy": 0, "control": 0}
    probe_ready: dict[str, threading.Event] = {
        "proxy": threading.Event(),
        "control": threading.Event(),
    }

    def emit(event: dict) -> None:
        event["wall_ns"] = time.time_ns()
        event["monotonic_ns"] = time.monotonic_ns()
        line = json.dumps(event, sort_keys=True)
        with output_lock:
            if event_file:
                event_file.write(line + "\n")
            if event["event"] in ("connected", "error"):
                print("PROBE " + line, flush=True)

    def probe(name: str, probe_family: int, probe_target: tuple) -> None:
        sequence = 0
        sock = None
        try:
            sock = socket.socket(probe_family, socket.SOCK_STREAM)
            sock.settimeout(args.timeout)
            sock.connect(probe_target)
            local = endpoint(sock.getsockname())
            remote = endpoint(sock.getpeername())
            emit({"event": "connected", "probe": name, "local": local, "remote": remote})
            probe_ready[name].set()
            while not stop.is_set():
                # Keep the payload byte-for-byte compatible with the original
                # reproducer so results remain comparable across builds.
                prefix = "persistent" if name == "proxy" else "control-persistent"
                payload = f"{prefix}-{sequence:08d}\n".encode()
                started_ns = time.monotonic_ns()
                sock.sendall(payload)
                reply = receive_exact(sock, len(payload))
                finished_ns = time.monotonic_ns()
                if reply != payload:
                    raise RuntimeError(f"{name} reply={reply!r} expected={payload!r}")
                probe_counts[name] += 1
                emit(
                    {
                        "event": "echo",
                        "probe": name,
                        "sequence": sequence,
                        "rtt_us": (finished_ns - started_ns) // 1000,
                    }
                )
                sequence += 1
                stop.wait(0.02)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            probe_errors[name].append(error)
            details = {"event": "error", "probe": name, "sequence": sequence, "error": error}
            try:
                if sock is None:
                    raise OSError("socket was not created")
                details["local"] = endpoint(sock.getsockname())
                details["remote"] = endpoint(sock.getpeername())
                details["tcp_info"] = tcp_info(sock)
            except OSError as info_error:
                details["tcp_info_error"] = f"{type(info_error).__name__}: {info_error}"
            emit(details)
            probe_ready[name].set()
            # Keep the failed socket inspectable while an external watchdog
            # snapshots namespace socket tables and the proxy diagnostics.
            stop.wait(args.failure_hold)
        finally:
            if sock is not None:
                sock.close()

    probe_threads = [
        threading.Thread(target=probe, args=("proxy", family, target), name="tcp-proxy-probe")
    ]
    if args.control_host:
        control_family = socket.AF_INET6 if ":" in args.control_host else socket.AF_INET
        probe_threads.append(
            threading.Thread(
                target=probe,
                args=("control", control_family, (args.control_host, args.control_port)),
                name="tcp-control-probe",
            )
        )
    for thread in probe_threads:
        thread.start()
    for name in ("proxy", "control") if args.control_host else ("proxy",):
        if not probe_ready[name].wait(args.timeout + 1):
            probe_errors[name].append("probe did not report connection readiness")

    churn_errors: list[str] = []
    started = time.monotonic()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            for wave in range(args.waves):
                start_barrier = threading.Barrier(args.flows + 1) if args.synchronized_start else None
                futures = []
                for index in range(args.flows):
                    source_port = args.min_port + wave * args.flows + index
                    payload = f"tcp-churn-{wave}-{index}\n".encode()
                    futures.append(
                        pool.submit(
                            exchange,
                            family,
                            target,
                            source_port,
                            payload,
                            args.timeout,
                            start_barrier,
                        )
                    )
                if start_barrier is not None:
                    start_barrier.wait()
                for future in futures:
                    try:
                        future.result()
                    except Exception as exc:
                        churn_errors.append(str(exc))
                time.sleep(args.interval)
        time.sleep(args.settle)
    finally:
        stop.set()
        for thread in probe_threads:
            thread.join()
        if event_file:
            event_file.close()

    elapsed = time.monotonic() - started
    all_probe_errors = probe_errors["proxy"] + probe_errors["control"]
    print(
        f"TCP churn: family=IPv{6 if family == socket.AF_INET6 else 4} flows={total} "
        f"probes={probe_counts['proxy']} control_probes={probe_counts['control']} elapsed={elapsed:.2f}s "
        f"churn_errors={len(churn_errors)} probe_errors={len(probe_errors['proxy'])} "
        f"control_errors={len(probe_errors['control'])}"
    )
    if churn_errors or all_probe_errors:
        for error in (churn_errors + all_probe_errors)[:20]:
            print(f"ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
