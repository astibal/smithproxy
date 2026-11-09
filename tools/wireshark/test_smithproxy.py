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
REFERENCE = Path(__file__).with_name("samples") / "smithproxy-reference.pcapng"


@unittest.skipIf(os.geteuid() == 0, "tshark disables user Lua as root")
@unittest.skipUnless(shutil.which("tshark"), "tshark is not installed")
class SmithproxyDissectorTest(unittest.TestCase):
    def run_tshark(self, *fields, capture=REFERENCE):
        with tempfile.TemporaryDirectory(prefix="smithproxy-tshark-") as temporary:
            directory = Path(temporary)
            readable_capture = directory / "reference.pcapng"
            dissector = directory / "smithproxy.lua"
            shutil.copy2(capture, readable_capture)
            shutil.copy2(DISSECTOR, dissector)
            command = ["tshark", "-r", str(readable_capture), "-X", f"lua_script:{dissector}",
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

        identity_rows = self.run_tshark("smithproxy.namespace", "smithproxy.version",
                                        "smithproxy.session_id",
                                        "smithproxy.proxy_session_key")
        sxpp_rows = [row for row in identity_rows if row.startswith("SXPP\t")]
        self.assertTrue(sxpp_rows)
        self.assertTrue(all("\t2\tProxy-DEADBEEF-PTR-12345678\t"
                            "tcp_192.0.2.10:51000-198.51.100.20:443" in row
                            for row in sxpp_rows))

    def test_sample_contains_native_http_and_tls(self):
        rows = self.run_tshark("frame.interface_name", "http.request.method", "http.host",
                               "tls.handshake.type", "tls.handshake.extensions_server_name",
                               "tls.handshake.extensions_alpn_str")
        self.assertIn("smithproxy-left\tGET\texample.test\t\t\t", rows)
        self.assertIn("smithproxy-right\t\t\t1\texample.test\th2,http/1.1", rows)
        self.assertIn("smithproxy-right\t\t\t2\t\t", rows)

    def test_reference_capture_is_reproducible(self):
        with tempfile.TemporaryDirectory(prefix="smithproxy-sample-") as temporary:
            generated = Path(temporary) / "reference.pcapng"
            subprocess.run([sys.executable, str(GENERATOR), "--output", str(generated)],
                           check=True, stdout=subprocess.DEVNULL)
            self.assertEqual(REFERENCE.read_bytes(), generated.read_bytes())


if __name__ == "__main__":
    unittest.main()
