#!/usr/bin/env python3
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("result")
parser.add_argument("--label", default="TLS transfer")
args = parser.parse_args()
data = json.load(open(args.result))
family = data.get("address_family", "")
for result in data["results"]:
    cpu = ""
    if "median_proxy_cpu_seconds_per_gib" in result:
        cpu = (f" proxy_cpu={result['median_proxy_cpu_seconds_per_gib']:.3f}s/GiB"
               f" range={result['min_proxy_cpu_seconds_per_gib']:.3f}-"
               f"{result['max_proxy_cpu_seconds_per_gib']:.3f}s/GiB")
    print(
        f"{args.label}: family={family} mode={result['mode']} concurrency={result['concurrency']} "
        f"median={result['median_mib_per_second']:.1f}MiB/s "
        f"range={result['min_mib_per_second']:.1f}-{result['max_mib_per_second']:.1f}MiB/s"
        f"{cpu}"
    )
