#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import pathlib
import statistics
import subprocess
import tempfile
import time


def process_cpu_seconds(pid):
    if pid is None:
        return None
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text().split()
    ticks = int(fields[13]) + int(fields[14])
    return ticks / float(__import__("os").sysconf("SC_CLK_TCK"))


def curl_command(args, mode, payload_file, run):
    url = f"https://origin.runner.lab/bulk/{args.bytes}?run={run}"
    resolved_host = f"[{args.host}]" if ":" in args.host else args.host
    command = [
        "curl", "--noproxy", "*", "--fail", "--silent", "--show-error",
        "--http1.1", "--max-time", str(args.timeout),
        "--cacert", args.ca_file,
        "--resolve", f"origin.runner.lab:443:{resolved_host}",
        "-H", "Expect:", "-o", "/dev/null",
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
    command = curl_command(args, mode, payload_file, run)
    cpu_started = process_cpu_seconds(args.pid)
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(
            lambda _: subprocess.run(command, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True),
            range(concurrency)))
    elapsed = time.monotonic() - started
    cpu_elapsed = (process_cpu_seconds(args.pid) - cpu_started
                   if cpu_started is not None else None)
    failures = [f"flow={index}: {result.stderr.strip()}"
                for index, result in enumerate(results) if result.returncode]
    if failures:
        raise RuntimeError(
            f"mode={mode} concurrency={concurrency} run={run}: "
            + "; ".join(failures))
    mib = args.bytes * concurrency / (1024 * 1024)
    result = {"seconds": elapsed, "mib_per_second": mib / elapsed}
    if cpu_elapsed is not None:
        result["proxy_cpu_seconds"] = cpu_elapsed
        result["proxy_cpu_seconds_per_gib"] = cpu_elapsed / (mib / 1024)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--concurrency", default="1,4,16")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--pid", type=int,
                        help="Smithproxy PID used for process CPU accounting")
    parser.add_argument("--tls-version", choices=("1.2", "1.3"))
    parser.add_argument("--cipher")
    args = parser.parse_args()
    concurrencies = [int(value) for value in args.concurrency.split(",")]

    with tempfile.TemporaryDirectory(prefix="smithproxy-transfer-") as directory:
        payload_file = pathlib.Path(directory) / "payload.bin"
        payload_file.touch()
        payload_file.chmod(0o600)
        with payload_file.open("r+b") as output:
            output.truncate(args.bytes)

        # Warm both TLS directions and the origin's worker path.
        transfer_once(args, "download", 1, payload_file, "warmup-download")
        transfer_once(args, "upload", 1, payload_file, "warmup-upload")

        output = {"host": args.host,
                  "address_family": "IPv6" if ":" in args.host else "IPv4",
                  "bytes_per_flow": args.bytes, "repeats": args.repeats,
                  "concurrency": concurrencies, "results": []}
        for concurrency in concurrencies:
            for mode in ("download", "upload"):
                samples = [transfer_once(args, mode, concurrency, payload_file, run)
                           for run in range(args.repeats)]
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
                output["results"].append(result)
        print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
