#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('validator', Path(__file__).with_name('verify-capture-metadata.py'))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def block(kind, body, endian):
    body += b'\0' * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + 'II', kind, size) + body + struct.pack(endian + 'I', size)


def capture(endian='<'):
    data = block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    identity = dict(session_id='session-test', proxy_session_key='tcp_192.0.2.1:50000-198.51.100.1:443')
    for ns, schema, extra in [('SXME', 'metadata', {'ja4': {'client': 'test-ja4', 'server': 'test-ja4s'}}),
                              ('SXST', 'statistics', {}), ('SXTL', 'tls', {'R': {'sni': 'origin.runner.lab'}})]:
        payload = json.dumps(dict(identity, schema='smithproxy.' + schema + '.v1', **extra)).encode()
        data += block(0xBAD, struct.pack(endian + 'I4sHHI', 67005, ns.encode(), 1, 1, len(payload)) + payload, endian)
    payload = ('2026-01-01T00:00:00Z,1,0,session-test,' + identity['proxy_session_key'] + ',1,R,tls,connection,,HANDSHAKE_READY,ok,').encode()
    return data + block(0xBAD, struct.pack(endian + 'I4sHHI', 67005, b'SXPP', 1, 2, len(payload)) + payload, endian)


class MetadataGateTest(unittest.TestCase):
    def run_capture(self, data):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'test.pcapng'
            path.write_bytes(data)
            return validator.validate([path])

    def test_both_byte_orders(self):
        for endian in ('<', '>'):
            self.assertEqual(self.run_capture(capture(endian))['controlled_tls_sessions'], 1)

    def test_missing_input_fails(self):
        with self.assertRaises(ValueError):
            validator.validate([])

    def test_unrelated_custom_block_is_allowed(self):
        self.assertEqual(self.run_capture(capture() + block(0xBAD, struct.pack('<I', 123), '<'))['status'], 'PASS')

    def test_duplicate_session_summary_fails(self):
        with self.assertRaises(ValueError):
            self.run_capture(capture() + capture())

    def test_session_id_cannot_move_between_flows(self):
        with self.assertRaisesRegex(ValueError, 'identity reused'):
            self.run_capture(capture() + capture().replace(b'50000', b'50001'))

    def test_truncation_fails(self):
        with self.assertRaises(ValueError):
            self.run_capture(capture()[:-1])

    def test_missing_fingerprint_fails(self):
        with self.assertRaises(ValueError):
            self.run_capture(capture().replace(b'"client"', b'"absent"'))

    def test_orphan_identity_fails(self):
        with self.assertRaises(ValueError):
            self.run_capture(capture().replace(b',session-test,', b',session-else,'))


if __name__ == '__main__':
    unittest.main()
