#!/usr/bin/env python3
import json, pathlib, sys
d = json.loads(pathlib.Path(sys.argv[1]).read_text()); l = d["latency_ms"]
print(f"Session-list summary: connections={d['connections']} samples={d['samples']} "
      f"sessions-min={d['sessions_min']} timeouts={d['timeouts']} "
      f"P50={l['p50']:.3f}ms P95={l['p95']:.3f}ms P99={l['p99']:.3f}ms "
      f"max={l['max']:.3f}ms output-max={d['output_bytes_max']}B")
