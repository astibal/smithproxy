#!/usr/bin/env python3
"""Exercise Smithproxy utility-mode startup and configuration failures."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def invoke(binary: Path, source: Path, runtime: Path, arguments: list[str],
           expected: int, needle: str) -> None:
    result = subprocess.run(
        [str(binary), *arguments], cwd=source,
        env={**os.environ, "SMITHPROXY_PID_FILE": str(runtime / "smithproxy.pid")},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    if result.returncode != expected or needle not in result.stdout:
        raise AssertionError(
            f"{arguments!r}: expected rc={expected} and {needle!r}, "
            f"got rc={result.returncode}:\n{result.stdout}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    source = args.source.resolve()

    with tempfile.TemporaryDirectory(prefix="smithproxy-main-e2e-") as temp:
        runtime = Path(temp)
        malformed = runtime / "malformed.cfg"
        malformed.write_text("settings = { definitely-not-valid")

        invoke(binary, source, runtime, ["--help"], 0, "Utility options")
        invoke(binary, source, runtime, ["--version"], 0, "+")
        invoke(binary, source, runtime, ["--unknown-option"], 1, "unknown option")
        invoke(binary, source, runtime, ["--tenant-index", "7"], 1, "unknown option")
        invoke(binary, source, runtime,
               ["--tenant-name", "missing-test-tenant", "--config-check-only",
                "--config-file", str(source / "etc/smithproxy.cfg")],
               1, "cannot load tenant config")
        invoke(binary, source, runtime,
               ["--config-check-only", "--config-file", str(runtime / "missing.cfg")],
               1, "Failed to load config file")
        invoke(binary, source, runtime,
               ["--config-check-only", "--config-file", str(malformed)],
               1, "Failed to load config file")
        invoke(binary, source, runtime,
               ["--config-check-only", "--config-file", str(source / "etc/smithproxy.cfg")],
               0, "Config file check OK")
        for verbosity in ("--debug", "--diagnose", "--dump", "--extreme"):
            invoke(binary, source, runtime,
                   [verbosity, "--tenant-name", "default", "--config-check-only",
                    "--config-file", str(source / "etc/smithproxy.cfg")],
                   0, "Config file check OK")

    print("PASS: main utility modes and config-check failures")


if __name__ == "__main__":
    main()
