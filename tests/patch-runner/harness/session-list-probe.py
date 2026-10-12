#!/usr/bin/env python3
"""Measure repeated detailed session-list snapshots over one CLI connection."""
import argparse, json, re, socket, statistics, time

ANSI_ESCAPE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
CLI_PROMPT = re.compile(
    rb"smithpr(?:oxy|\xe2\x8c\x80xy)\([^\r\n]*\)"
    rb"(?:<\*>|<!>)*(?:\(config:/[^\r\n]*\))?[#>] "
)
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

def is_cli_prompt(data, markers):
    """Recognize the complete Smithproxy prompt, not arbitrary output '# '."""
    plain = ANSI_ESCAPE.sub(b"", data)
    tail = re.split(rb"[\r\n]", plain)[-1]
    return CLI_PROMPT.fullmatch(tail) is not None and any(
        tail.endswith(marker) for marker in markers)

def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--connections", type=int, default=256)
    p.add_argument("--samples", type=int, default=24)
    p.add_argument("--p95-limit-ms", type=float, default=1000)
    p.add_argument("--max-limit-ms", type=float, default=3000)
    p.add_argument("--timeout", type=float, default=6)
    a = p.parse_args()
    sock = socket.create_connection(("127.0.0.1", 50000), timeout=a.timeout)
    sock.settimeout(a.timeout)
    def prompt(*markers):
        data = bytearray()
        deadline = time.monotonic() + a.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"CLI prompt deadline exceeded after {len(data)} bytes; "
                    f"wire tail={bytes(data[-256:])!r}"
                )
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(65536)
            except TimeoutError as error:
                raise TimeoutError(
                    f"CLI prompt receive timed out after {len(data)} bytes; "
                    f"wire tail={bytes(data[-256:])!r}"
                ) from error
            if not chunk: raise RuntimeError("CLI closed before prompt")
            data.extend(chunk)
            if len(data) > MAX_RESPONSE_BYTES:
                raise RuntimeError("CLI response exceeded 64 MiB")
            if is_cli_prompt(data, markers):
                return bytes(data)
    prompt(b"> "); sock.sendall(b"enable\r\n"); prompt(b"# ")
    rows = []
    for sample in range(a.samples):
        level = 6 if sample % 2 == 0 else 8
        started = time.perf_counter_ns()
        sock.sendall(f"diag proxy session list {level}\r\n".encode())
        # A decorated prompt contains ANSI sequences between ')' and the
        # privilege marker.  Accept either prompt here and validate the
        # command by its session rows; an unprivileged rejection therefore
        # still fails deterministically instead of waiting forever.
        output = prompt(b"# ", b"> ")
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        sessions = output.count(b"MitM|")
        if b"timed out" in output: raise RuntimeError(f"snapshot {sample + 1}: timeout")
        if sessions < a.connections:
            raise RuntimeError(f"snapshot {sample + 1}: {sessions}/{a.connections} sessions")
        rows.append((elapsed, len(output), sessions))
    sock.sendall(b"quit\r\n"); sock.close()
    latencies = [row[0] for row in rows]
    result = {"connections": a.connections, "samples": len(rows), "levels": [6, 8],
              "latency_ms": {"min": min(latencies), "p50": statistics.median(latencies),
                             "p95": percentile(latencies, .95), "p99": percentile(latencies, .99),
                             "max": max(latencies)},
              "output_bytes_max": max(row[1] for row in rows),
              "sessions_min": min(row[2] for row in rows), "timeouts": 0}
    print(json.dumps(result, sort_keys=True))
    if result["latency_ms"]["p95"] > a.p95_limit_ms: raise RuntimeError("session-list p95 limit")
    if result["latency_ms"]["max"] > a.max_limit_ms: raise RuntimeError("session-list max limit")

if __name__ == "__main__": main()
