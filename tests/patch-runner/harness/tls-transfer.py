#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import ipaddress
import math
import os
import pathlib
import resource
import statistics
import subprocess
import sys
import tempfile
import time


def process_cpu_seconds(pid):
    """Read process CPU, excluding wall time and allowing spaces in comm."""
    if pid is None:
        return None
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def child_cpu_seconds():
    """Account for the reaped native clients, including all concurrent flows."""
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def native_command(args, mode, payload_file, host):
    """Use the independent C++ endpoint; the driver never handles payload data."""
    command = [args.h3_client, "-q", "--exit-on-all-streams-close",
               "--handshake-timeout=10s", f"--timeout={args.timeout}s",
               "--sni=origin.runner.lab"]
    if mode == "upload":
        command += ["--http-method=POST", "-d", str(payload_file)]
    return command + [host, "443", f"https://origin.runner.lab/bulk/{args.bytes}"]


def curl_command(args, mode, payload_file, run, host):
    """Keep curl as the TLS client and an independent native H3 cross-check."""
    url = f"https://origin.runner.lab/bulk/{args.bytes}?run={run}"
    resolved_host = f"[{host}]" if ":" in host else host
    command = [
        args.curl, "--noproxy", "*", "--fail", "--silent", "--show-error",
        "--http3-only" if args.protocol == "h3" else "--http1.1", "--max-time", str(args.timeout),
        "--cacert", args.ca_file,
        "--resolve", f"origin.runner.lab:443:{resolved_host}",
        "-H", "Expect:", "-o", "/dev/null", "--write-out", "%{json}",
    ]
    if args.tls_version:
        command += [f"--tlsv{args.tls_version}", "--tls-max", args.tls_version]
    if args.cipher:
        option = "--tls13-ciphers" if args.tls_version == "1.3" else "--ciphers"
        command += [option, args.cipher]
    if mode == "upload":
        command += ["--data-binary", f"@{payload_file}"]
    command.append(url)
    return command


def transfer_once(args, mode, concurrency, payload_file, run):
    """Time a checked transfer batch and report CPU at each measured endpoint."""
    commands = [(native_command(args, mode, payload_file, args.hosts[i % len(args.hosts)])
                 if args.h3_client else curl_command(args, mode, payload_file, run,
                                                    args.hosts[i % len(args.hosts)]))
                for i in range(concurrency)]
    environment = dict(os.environ)
    if args.h3_client:
        environment["SSL_CERT_FILE"] = args.ca_file
    server_pids = (json.loads(args.origin_pid_file.read_text())["pids"]
                   if args.origin_pid_file else [])
    server_before = {pid: process_cpu_seconds(pid) for pid in server_pids}
    client_before = child_cpu_seconds()
    cpu_started = process_cpu_seconds(args.pid)
    def run_client(command):
        # Completion latency includes process launch and handshake, not just RTT.
        start = time.monotonic()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=environment, timeout=args.timeout)
        return result, time.monotonic() - start

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        completed = list(pool.map(run_client, commands))
    elapsed = time.monotonic() - started
    results = [result for result, _ in completed]
    latencies = sorted(duration for _, duration in completed)
    cpu_elapsed = (process_cpu_seconds(args.pid) - cpu_started
                   if cpu_started is not None else None)
    client_elapsed = child_cpu_seconds() - client_before
    server_elapsed = {pid: process_cpu_seconds(pid) - before
                      for pid, before in server_before.items()}
    failures = [f"flow={index}: {result.stderr.strip()}"
                for index, result in enumerate(results) if result.returncode]
    if failures:
        raise RuntimeError(
            f"mode={mode} concurrency={concurrency} run={run}: "
            + "; ".join(failures))
    flows = []
    for index, response in enumerate(results):
        if args.h3_client:
            records = [json.loads(line) for line in response.stdout.splitlines()
                       if line.startswith('{"h3_benchmark":')]
            if len(records) != 1:
                raise RuntimeError(f"flow={index}: missing H3 completion: {response.stderr.strip()}")
            measured = records[0]
            # A demo program's exit status alone does not prove a completed
            # transfer. Require HTTP success, clean stream close and payload.
            if (measured["error_code"] not in (0, 256) or measured["nonzero"]
                    or measured["http_code"] != 200):
                raise RuntimeError(f"flow={index}: invalid H3 completion: {measured}")
        else:
            measured = json.loads(response.stdout)
        # The TLS fixture can answer HTTP/1.0 even when curl offers HTTP/1.1.
        expected_versions = {"3"} if args.protocol == "h3" else {"1", "1.0", "1.1"}
        direction = "size_download" if mode == "download" else "size_upload"
        if str(measured["http_version"]) not in expected_versions or int(measured[direction]) != args.bytes:
            raise RuntimeError(f"flow={index}: HTTP/{measured['http_version']}, "
                               f"{direction}={measured[direction]}, expected={args.bytes} ({args.protocol})")
        flows.append({key: measured[key] for key in
                      ("http_version", "http_code", "size_download", "size_upload")})
    mib = args.bytes * concurrency / (1024 * 1024)
    result = {"seconds": elapsed, "mib_per_second": mib / elapsed, "flows": flows,
              "client_cpu_seconds": client_elapsed,
              "client_cpu_percent": client_elapsed / elapsed * 100,
              "completion_p50_seconds": statistics.median(latencies),
              "completion_p95_seconds": latencies[math.ceil(.95 * len(latencies)) - 1],
              "completion_seconds": [duration for _, duration in completed]}
    if cpu_elapsed is not None:
        result["proxy_cpu_seconds"] = cpu_elapsed
        result["proxy_cpu_seconds_per_gib"] = cpu_elapsed / (mib / 1024)
    if server_elapsed:
        result["origin_cpu_seconds"] = sum(server_elapsed.values())
        result["origin_cpu_percent"] = result["origin_cpu_seconds"] / elapsed * 100
        result["origin_worker_cpu_percent"] = {
            str(pid): used / elapsed * 100 for pid, used in server_elapsed.items()}
        result["origin_busiest_cpu_percent"] = max(result["origin_worker_cpu_percent"].values())
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=("h1", "h3"), default="h1")
    parser.add_argument("--curl", default="curl")
    parser.add_argument("--h3-client", help="Native ngtcp2 benchmark client; H3 only")
    parser.add_argument("--origin-pid-file", type=pathlib.Path,
                        help="Native origin worker PID manifest for CPU accounting")
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--hosts", help="Comma-separated same-family destinations, round-robin per flow")
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--concurrency", default="1,4,16")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--cooldown-seconds", type=float, default=0,
                        help="Wait outside timing before each sample to separate connection cleanup")
    parser.add_argument("--pid", type=int,
                        help="Smithproxy PID used for process CPU accounting")
    parser.add_argument("--tls-version", choices=("1.2", "1.3"))
    parser.add_argument("--cipher")
    parser.add_argument("--output", type=pathlib.Path,
                        help="Checkpoint completed measurements even if a later transfer fails")
    args = parser.parse_args()
    if args.protocol == "h3" and (args.tls_version or args.cipher):
        parser.error("H3 uses QUIC TLS configuration, not TCP TLS cipher switches")
    if args.h3_client and args.protocol != "h3":
        parser.error("--h3-client requires --protocol h3")
    args.hosts = args.hosts.split(",") if args.hosts else [args.host]
    if len(args.hosts) > 1 and len({ipaddress.ip_address(host).version for host in args.hosts}) != 1:
        parser.error("all destinations must use the same address family")
    args.host = args.hosts[0]
    concurrencies = [int(value) for value in args.concurrency.split(",")]

    if not math.isfinite(args.cooldown_seconds) or args.cooldown_seconds < 0:
        parser.error("cooldown-seconds must be finite and nonnegative")
    if args.bytes <= 0 or args.repeats <= 0 or not concurrencies or min(concurrencies) <= 0:
        parser.error("bytes, repeats and concurrency must be positive")

    with tempfile.TemporaryDirectory(prefix="smithproxy-transfer-") as directory:
        payload_file = pathlib.Path(directory) / "payload.bin"
        payload_file.touch()
        payload_file.chmod(0o600)
        with payload_file.open("r+b") as output:
            output.truncate(args.bytes)

        # Warm both TLS directions and the origin's worker path.
        transfer_once(args, "download", len(args.hosts), payload_file, "warmup-download")
        transfer_once(args, "upload", len(args.hosts), payload_file, "warmup-upload")

        output = {"host": args.host, "hosts": args.hosts, "protocol": args.protocol, "curl": args.curl,
                  "client": args.h3_client or args.curl,
                  "origin": (json.loads(args.origin_pid_file.read_text())
                             if args.origin_pid_file else None),
                  "address_family": "IPv6" if ":" in args.host else "IPv4",
                  "cooldown_seconds": args.cooldown_seconds,
                  "bytes_per_flow": args.bytes, "repeats": args.repeats,
                  "concurrency": concurrencies, "results": []}
        def checkpoint():
            if args.output:
                temporary = args.output.with_suffix(args.output.suffix + ".tmp")
                temporary.write_text(json.dumps(output, indent=2, sort_keys=True))
                temporary.replace(args.output)

        checkpoint()
        for concurrency in concurrencies:
            for mode in ("download", "upload"):
                samples = []
                for run in range(args.repeats):
                    # Optional isolation of connection cleanup; this wait is
                    # outside transfer_once's wall-clock and CPU accounting.
                    if args.cooldown_seconds:
                        time.sleep(args.cooldown_seconds)
                    samples.append(transfer_once(args, mode, concurrency, payload_file, run))
                rates = [sample["mib_per_second"] for sample in samples]
                result = {
                    "mode": mode,
                    "concurrency": concurrency,
                    "samples": samples,
                    "median_mib_per_second": statistics.median(rates),
                    "min_mib_per_second": min(rates),
                    "max_mib_per_second": max(rates),
                }
                cpu_rates = [sample["proxy_cpu_seconds_per_gib"]
                             for sample in samples
                             if "proxy_cpu_seconds_per_gib" in sample]
                if cpu_rates:
                    result["median_proxy_cpu_seconds_per_gib"] = statistics.median(cpu_rates)
                    result["min_proxy_cpu_seconds_per_gib"] = min(cpu_rates)
                    result["max_proxy_cpu_seconds_per_gib"] = max(cpu_rates)
                for endpoint in ("client", "origin", "origin_busiest"):
                    percentages = [sample[f"{endpoint}_cpu_percent"] for sample in samples
                                   if f"{endpoint}_cpu_percent" in sample]
                    if percentages:
                        result[f"median_{endpoint}_cpu_percent"] = statistics.median(percentages)
                output["results"].append(result)
                checkpoint()
                print(f"Measured {args.protocol} {output['address_family']} {mode} "
                      f"concurrency={concurrency}: {statistics.median(rates):.2f} MiB/s",
                      file=sys.stderr, flush=True)
        print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
