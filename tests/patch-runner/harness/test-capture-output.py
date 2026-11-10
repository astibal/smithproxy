"""Hermetic regressions for the independent GRE/PCAPNG receiver."""
import pathlib
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

from gre_pcapng import restore
from capture_tls_cases import cases


def block(kind, payload=b''):
    size = 12 + len(payload)
    return struct.pack('<II', kind, size) + payload + struct.pack('<I', size)


class ReceiverTests(unittest.TestCase):
    def receive(self, payloads):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / 'restored.pcapng'
            source = pathlib.Path(directory) / 'wire.pcap'
            source.write_bytes(b'test-input')
            result = types.SimpleNamespace(stdout='\n'.join(p.hex() for p in payloads))
            with patch('gre_pcapng.subprocess.run', return_value=result):
                path, counts = restore(source, output)
                return path.read_bytes(), counts

    def test_multiple_blocks_and_secrets_preserve_order(self):
        packets = block(6) + block(6)
        secret = block(10, b'test')
        raw, counts = self.receive([secret, packets])
        self.assertEqual(counts, {10: 1, 6: 2})
        self.assertEqual(raw[48:], secret + packets)

    def test_empty_or_secret_only_fails(self):
        for payloads in ([], [block(10)]):
            with self.subTest(payloads=payloads), self.assertRaises(AssertionError):
                self.receive(payloads)

    def test_truncated_or_invalid_length_fails(self):
        for payload in (b'123', block(6)[:-1], block(6)[:-4] + b'\0' * 4,
                        struct.pack('<III', 6, 0, 0)):
            with self.subTest(payload=payload), self.assertRaises(AssertionError):
                self.receive([payload])

    def test_tls_cases_have_distinct_bidirectional_markers(self):
        self.assertEqual([version for _, version, _, _ in cases()], ['1.2', '1.3'])
        for number, _, request, response in cases():
            self.assertIn(f'CMX{number}C'.encode(), request)
            self.assertIn(f'CMX{number}S'.encode(), response)


if __name__ == '__main__':
    unittest.main()
