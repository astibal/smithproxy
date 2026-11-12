#!/usr/bin/env python3
"""Start native H3 origins; Python never handles a datagram or application byte.

The benchmark uses stable tuples, so SO_REUSEPORT can spread independent
connections across origin processes without changing the destination IP/port.
This is a test-server arrangement, not Smithproxy's CID routing design.
"""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import time


def wait_for_listeners(workers, port):
    """Confirm every worker bound its socket before announcing readiness."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if any(worker.poll() is not None for worker in workers):
            raise RuntimeError("native origin exited during startup")
        sockets = subprocess.check_output(
            ["ss", "-H", "-lunp", f"sport = :{port}"], text=True)
        if all(f"pid={worker.pid}," in sockets for worker in workers):
            return
        time.sleep(.05)
    raise RuntimeError("not all native origins bound their sockets")


def stop_workers(workers):
    """Reap every owned worker, including partial startup and interrupted runs."""
    for worker in workers:
        if worker.poll() is None:
            worker.terminate()
    for worker in workers:
        try:
            worker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait()


def main():
    """Prepare sparse zero payloads and supervise the native server processes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--pid-file", type=Path, required=True)
    parser.add_argument("--bytes", type=int, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()
    if not 0 < args.bytes <= 1024**3 or not 1 <= args.workers <= 16:
        parser.error("bytes must be 1..1 GiB and workers 1..16")
    payloads = args.directory / "bulk"
    payloads.mkdir(parents=True, exist_ok=False)
    with (payloads / str(args.bytes)).open("wb") as output:
        output.truncate(args.bytes)

    def interrupted(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    workers = []
    try:
        for _ in range(args.workers):
            workers.append(subprocess.Popen([
                str(args.server), "-q", "-d", str(args.directory), "*", str(args.port),
                str(args.key), str(args.certificate)]))
        wait_for_listeners(workers, args.port)
        args.pid_file.write_text(json.dumps({
            "backend": "ngtcp2/nghttp3", "server": str(args.server),
            "workers": args.workers, "pids": [worker.pid for worker in workers]}))
        print(f"READY h3-origin native workers={args.workers} port={args.port}", flush=True)
        while True:
            if any(worker.poll() is not None for worker in workers):
                raise RuntimeError("native origin worker exited")
            time.sleep(.5)
    finally:
        stop_workers(workers)


if __name__ == "__main__":
    main()
