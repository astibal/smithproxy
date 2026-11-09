#!/usr/bin/env python3
"""Black-box tests for the Smithproxy PCAPNG custom-block dissector."""

import os
import shutil
import subprocess
import sys
import struct
import json
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
            environment = os.environ.copy()
            environment["XDG_CONFIG_HOME"] = str(directory / "config")
            environment["WIRESHARK_CONFIG_DIR"] = str(directory / "config" / "wireshark")
            return subprocess.run(command, check=True, capture_output=True,
                                  text=True, env=environment).stdout.splitlines()

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

    def test_unknown_types_and_versions_remain_opaque(self):
        for field_offset in (16, 18):
            with self.subTest(field_offset=field_offset), tempfile.TemporaryDirectory() as temporary:
                data = bytearray(REFERENCE.read_bytes())
                offset = 0
                while offset < len(data):
                    kind, length = struct.unpack_from("<II", data, offset)
                    if kind in (0xBAD, 0x40000BAD):
                        struct.pack_into("<H", data, offset + field_offset, 99)
                    offset += length
                capture = Path(temporary) / "unknown.pcapng"
                capture.write_bytes(data)
                rows = self.run_tshark("smithproxy.namespace", "smithproxy.schema",
                                      "smithproxy.pp.event", "smithproxy.session_id",
                                      "_ws.expert.message", capture=capture)
                custom = [row for row in rows if row.startswith("SX")]
                self.assertTrue(custom)
                for row in custom:
                    fields = row.split("\t")
                    self.assertEqual(fields[1:4], ["", "", ""])
                    self.assertIn("99", fields[4])

    def test_native_flow_key_prefixes_both_endpoints(self):
        for protocol, source, destination in [('tcp', '192.0.2.1', '198.51.100.1'),
                                              ('tcp', '2001:db8::1', '2001:db8::2'),
                                              ('ssli', '192.0.2.1', '198.51.100.1'),
                                              ('ssli', '2001:db8::1', '2001:db8::2')]:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                payload = json.dumps({'schema': 'smithproxy.metadata.v1',
                                      'session_id': 'native-key-test',
                                      'proxy_session_key': f'{protocol}_{source}:50000-{protocol}_{destination}:443'}).encode()
                body = struct.pack('<I4sHHI', 67005, b'SXME', 1, 1, len(payload)) + payload
                body += b'\0' * (-len(body) % 4)
                size = len(body) + 12
                custom = struct.pack('<II', 0xBAD, size) + body + struct.pack('<I', size)
                capture = Path(temporary) / 'native-key.pcapng'
                capture.write_bytes(REFERENCE.read_bytes() + custom)
                rows = self.run_tshark('smithproxy.session_id', 'smithproxy.flow.src',
                                      'smithproxy.flow.dst', 'smithproxy.flow.src_port',
                                      'smithproxy.flow.dst_port', capture=capture)
                self.assertIn(f'native-key-test\t{source}\t{destination}\t50000\t443', rows)


if __name__ == "__main__":
    unittest.main()
