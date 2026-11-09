#!/usr/bin/env python3
"""Black-box tests for the SPQ1 Wireshark dissector."""

import os
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
    def tshark_environment(self, temporary_path: Path) -> dict[str, str]:
        """Load the tested Lua file, not a user's installed copy or preferences."""
        config = temporary_path / "config"
        plugins = temporary_path / "plugins"
        config.mkdir()
        plugins.mkdir()

        # Keep the caller's environment intact. Both locations matter: Lua
        # plugins can also live in the personal configuration directory.
        environment = os.environ.copy()
        environment["WIRESHARK_CONFIG_DIR"] = str(config)
        environment["WIRESHARK_PLUGIN_DIR"] = str(plugins)
        return environment

    @unittest.skipIf(
        os.geteuid() == 0,
        "tshark disables user Lua dissectors when running as superuser",
    )
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
                env=self.tshark_environment(temporary_path),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        self.assertEqual(
            ["GET\thttps://origin.runner.lab/demo"],
            result.stdout.strip().splitlines(),
        )

    @unittest.skipIf(
        os.geteuid() == 0,
        "tshark disables user Lua dissectors when running as superuser",
    )
    @unittest.skipUnless(shutil.which("tshark"), "tshark is not installed")
    def test_decodes_spq1_after_native_quic_on_same_tuple(self) -> None:
        """Do not let native QUIC conversation binding hide later SPQ1 records."""
        with tempfile.TemporaryDirectory(prefix="spq1-mixed-tshark-") as temporary:
            temporary_path = Path(temporary)
            capture = temporary_path / "mixed.pcap"
            dissector = temporary_path / "spquic.lua"
            shutil.copy2(DISSECTOR, dissector)

            subprocess.run(
                [sys.executable, str(DEMO_GENERATOR), "--output", str(capture),
                 "--prepend-native-quic"],
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
                    "-e", "sphttp3.url",
                ],
                env=self.tshark_environment(temporary_path),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        self.assertEqual(
            ["https://origin.runner.lab/demo"],
            result.stdout.strip().splitlines(),
        )


if __name__ == "__main__":
    unittest.main()
