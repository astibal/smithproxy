#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import pathlib
import statistics
import subprocess
import tempfile
import time


def curl_command(args, mode, payload_file, run):
    url = f"https://origin.runner.lab/bulk/{args.bytes}?run={run}"
    command = [
        "curl", "--noproxy", "*", "--fail", "--silent", "--show-error",
        "--http1.1", "--max-time", str(args.timeout),
        "--cacert", args.ca_file,
        "--resolve", f"origin.runner.lab:443:{args.host}",
        "-H", "Expect:", "-o", "/dev/null",
    ]
    if mode == "upload":
        command += ["--data-binary", f"@{payload_file}"]
    command.append(url)
    return command


def transfer_once(args, mode, concurrency, payload_file, run):
    command = curl_command(args, mode, payload_file, run)
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(
            lambda _: subprocess.run(command, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True),
            range(concurrency)))
    elapsed = time.monotonic() - started
    failures = [result.stderr.strip() for result in results if result.returncode]
    if failures:
        raise RuntimeError("; ".join(failures))
    mib = args.bytes * concurrency / (1024 * 1024)
    return {"seconds": elapsed, "mib_per_second": mib / elapsed}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="198.18.20.2")
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--concurrency", default="1,4,16")
    parser.add_argument("--timeout", type=int, default=120)
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

        output = {"bytes_per_flow": args.bytes, "repeats": args.repeats,
                  "concurrency": concurrencies, "results": []}
        for concurrency in concurrencies:
            for mode in ("download", "upload"):
                samples = [transfer_once(args, mode, concurrency, payload_file, run)
                           for run in range(args.repeats)]
                rates = [sample["mib_per_second"] for sample in samples]
                output["results"].append({
                    "mode": mode,
                    "concurrency": concurrency,
                    "samples": samples,
                    "median_mib_per_second": statistics.median(rates),
                    "min_mib_per_second": min(rates),
                    "max_mib_per_second": max(rates),
                })
        print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
