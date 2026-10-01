#!/usr/bin/env python3
import json
import sys

data = json.load(open(sys.argv[1]))
for result in data["results"]:
    print(
        f"TLS transfer: mode={result['mode']} concurrency={result['concurrency']} "
        f"median={result['median_mib_per_second']:.1f}MiB/s "
        f"range={result['min_mib_per_second']:.1f}-{result['max_mib_per_second']:.1f}MiB/s"
    )
