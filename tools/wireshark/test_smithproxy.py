#!/usr/bin/env python3
"""Black-box tests for the Smithproxy PCAPNG custom-block dissector."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


DISSECTOR = Path(__file__).with_name("smithproxy.lua")
GENERATOR = Path(__file__).with_name("generate_sample.py")


@unittest.skipIf(os.geteuid() == 0, "tshark disables user Lua as root")
@unittest.skipUnless(shutil.which("tshark"), "tshark is not installed")
class SmithproxyDissectorTest(unittest.TestCase):
    def run_tshark(self, *fields):
        with tempfile.TemporaryDirectory(prefix="smithproxy-tshark-") as temporary:
            directory = Path(temporary)
            capture = directory / "sample.pcapng"
            dissector = directory / "smithproxy.lua"
            shutil.copy2(DISSECTOR, dissector)
            subprocess.run([sys.executable, str(GENERATOR), "--output", str(capture)],
                           check=True, stdout=subprocess.DEVNULL)
            command = ["tshark", "-r", str(capture), "-X", f"lua_script:{dissector}",
                       "-T", "fields"]
            for field in fields:
                command.extend(["-e", field])
            return subprocess.run(command, check=True, capture_output=True,
                                  text=True).stdout.splitlines()

    def test_decodes_custom_namespaces_and_protocol_trace(self):
        rows = self.run_tshark("smithproxy.namespace", "smithproxy.schema",
                               "smithproxy.pp.event")
        self.assertIn("SXTL\tsmithproxy.tls.v1\t", rows)
        self.assertIn("SXME\tsmithproxy.metadata.v1\t", rows)
        self.assertIn("SXST\tsmithproxy.statistics.v1\t", rows)
        self.assertIn("SXPP\t\tSERVER_HELLO", rows)
        self.assertIn("SXPP\t\tDECIDED", rows)

    def test_sample_contains_native_http_and_tls(self):
        rows = self.run_tshark("http.request.method", "http.host", "tls.handshake.type",
                               "tls.handshake.extensions_server_name")
        self.assertIn("GET\texample.test\t\t", rows)
        self.assertIn("\t\t1\texample.test", rows)
        self.assertIn("\t\t2\t", rows)


if __name__ == "__main__":
    unittest.main()
