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


def capture(endian='<', http_fingerprints=('test-ja4h',)):
    data = block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    identity = dict(session_id='session-test', proxy_session_key='tcp_192.0.2.1:50000-198.51.100.1:443')
    for seq, (side, event) in enumerate((('R', 'HANDSHAKE_STARTED'), ('R', 'HANDSHAKE_READY'),
                                        ('L', 'HANDSHAKE_STARTED'), ('L', 'HANDSHAKE_READY')), 1):
        payload = (f'2026-01-01T00:00:00Z,1,0,session-test,{identity["proxy_session_key"]},'
                   f'{seq},{side},tls,connection,,{event},ok,').encode()
        data += block(0xBAD, struct.pack(endian + 'I4sHHI', 67005, b'SXPP', 1, 2, len(payload)) + payload, endian)
    for ns, schema, extra in [('SXME', 'metadata', {'ja4': {'client': 'test-ja4', 'server': 'test-ja4s', 'http': http_fingerprints}}),
                              ('SXST', 'statistics', {}), ('SXTL', 'tls', {'transport': 'tcp', 'R': {'sni': 'origin.runner.lab'}})]:
        payload = json.dumps(dict(identity, schema='smithproxy.' + schema + '.v1', **extra)).encode()
        data += block(0xBAD, struct.pack(endian + 'I4sHHI', 67005, ns.encode(), 1, 1, len(payload)) + payload, endian)
    return data


def tcp_packets(flags=(2, 18, 16)):
    result = block(1, struct.pack('<HHI', 113, 0, 65535), '<')
    for flag in flags:
        ip = bytearray(40)
        ip[0], ip[9], ip[33] = 0x45, 6, flag
        ip[12:16], ip[16:20] = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1])
        struct.pack_into('!HH', ip, 20, 50000, 443)
        if flag == 18:
            ip[12:16], ip[16:20] = ip[16:20], ip[12:16]
            struct.pack_into('!HH', ip, 20, 443, 50000)
        packet = bytes(16) + ip
        result += block(6, struct.pack('<IIIII', 0, 0, 1, len(packet), len(packet)) + packet, '<')
    return result


class MetadataGateTest(unittest.TestCase):
    def tls_event(self, side, event, session='tls-test'):
        return dict(session_id=session, proxy_session_key='tcp_192.0.2.1:50000-198.51.100.1:443',
                    component='tls', side=side, event=event)

    def test_tls_profile_requires_both_ready_legs(self):
        states = {}
        profile = dict(self.tls_event('P', ''), transport='tcp')
        for side in ('R', 'L'):
            validator.observe_tls('SXPP', self.tls_event(side, 'HANDSHAKE_STARTED'), states)
            with self.assertRaisesRegex(ValueError, 'both ready'):
                validator.observe_tls('SXTL', profile, states)
            validator.observe_tls('SXPP', self.tls_event(side, 'HANDSHAKE_READY'), states)
        validator.observe_tls('SXTL', profile, states)

    def test_tls_terminal_without_start_fails(self):
        for event in ('HANDSHAKE_READY', 'HANDSHAKE_FAILED'):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, 'active handshake'):
                validator.observe_tls('SXPP', self.tls_event('R', event), {})

    def test_failed_tls_cannot_become_ready(self):
        states = {}
        for event in ('HANDSHAKE_STARTED', 'HANDSHAKE_FAILED'):
            validator.observe_tls('SXPP', self.tls_event('R', event), states)
        with self.assertRaisesRegex(ValueError, 'active handshake'):
            validator.observe_tls('SXPP', self.tls_event('R', 'HANDSHAKE_READY'), states)

    def test_reused_tuple_has_independent_tls_sessions(self):
        states = {}
        for session in ('first', 'second'):
            for side in ('L', 'R'):
                validator.observe_tls('SXPP', self.tls_event(side, 'HANDSHAKE_STARTED', session), states)
        for session in ('second', 'first'):
            for side in ('R', 'L'):
                validator.observe_tls('SXPP', self.tls_event(side, 'HANDSHAKE_READY', session), states)
            validator.observe_tls('SXTL', dict(self.tls_event('P', '', session), transport='tcp'), states)

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
        for key in (b'"client"', b'"server"'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'missing JA4/JA4S'):
                self.run_capture(capture().replace(key, b'"absent"'))

    def test_handshake_before_metadata_passes(self):
        data = capture()
        self.assertEqual(self.run_capture(data[:28] + tcp_packets() + data[28:])['status'], 'PASS')

    def test_missing_http_fingerprint_fails(self):
        with self.assertRaisesRegex(ValueError, 'missing JA4H'):
            self.run_capture(capture().replace(b'"http"', b'"none"'))

    def test_empty_or_invalid_http_fingerprints_fail(self):
        for value in ([], None, [''], [42], 'not-an-array'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'missing JA4H'):
                self.run_capture(capture(http_fingerprints=value))

    def test_multiple_http_fingerprints_are_preserved(self):
        self.assertEqual(self.run_capture(capture(http_fingerprints=['first', 'second']))['status'], 'PASS')

    def test_metadata_before_handshake_fails(self):
        with self.assertRaisesRegex(ValueError, 'precedes synthetic'):
            self.run_capture(capture() + tcp_packets())

    def test_missing_final_ack_fails(self):
        data = capture()
        with self.assertRaisesRegex(ValueError, 'interrupts synthetic'):
            self.run_capture(data[:28] + tcp_packets((2, 18)) + data[28:])

    def test_synack_without_syn_fails(self):
        data = capture()
        with self.assertRaisesRegex(ValueError, 'without preceding SYN'):
            self.run_capture(data[:28] + tcp_packets((18, 16)) + data[28:])

    def test_reordered_protocol_events_fail(self):
        data = capture()
        # Existing seq=1..4 followed by seq=0, with distinct sequence numbers.
        payload = b'2026-01-01,1,0,session-test,tcp_192.0.2.1:50000-198.51.100.1:443,0,R,tcp,connection,,CONNECTED,ok,'
        with self.assertRaisesRegex(ValueError, 'out of sequence'):
            self.run_capture(data + block(0xBAD, struct.pack('<I4sHHI', 67005, b'SXPP', 1, 2, len(payload)) + payload, '<'))

    def test_orphan_identity_fails(self):
        with self.assertRaises(ValueError):
            self.run_capture(capture().replace(b',session-test,', b',session-else,'))


if __name__ == '__main__':
    unittest.main()
