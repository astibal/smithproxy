#!/usr/bin/env python3
"""Black-box tests for the SPQ1 Wireshark dissector."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1]
DISSECTOR = Path(__file__).with_name("spquic.lua")
DEMO_GENERATOR = TOOLS / "generate-spquic-demo.py"


class Spq1DissectorTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("tshark"), "tshark is not installed")
    def test_composes_request_url(self) -> None:
        """Combine H3 pseudo-headers into one stable, filterable URL field."""
        with tempfile.TemporaryDirectory(prefix="spq1-tshark-") as temporary:
            temporary_path = Path(temporary)
            capture = temporary_path / "request.pcap"
            dissector = temporary_path / "spquic.lua"
            shutil.copy2(DISSECTOR, dissector)

            subprocess.run(
                [sys.executable, str(DEMO_GENERATOR), "--output", str(capture)],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            result = subprocess.run(
                [
                    "tshark",
                    "-r", str(capture),
                    "-X", f"lua_script:{dissector}",
                    "-Y", "sphttp3.url",
                    "-T", "fields",
                    "-e", "sphttp3.method",
                    "-e", "sphttp3.url",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertEqual(
            ["GET\thttps://origin.runner.lab/demo"],
            result.stdout.strip().splitlines(),
        )


if __name__ == "__main__":
    unittest.main()
