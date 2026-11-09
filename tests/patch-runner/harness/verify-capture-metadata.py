#!/usr/bin/env python3
"""Strict first-stage live metadata gate; no dependency on the producer decoder."""
import collections
import csv
import io
import hashlib
import json
from pathlib import Path
import struct
import ssl
import sys
import ipaddress
import re


def flow_key(source, source_port, destination, destination_port):
    return tuple(sorted(((str(ipaddress.ip_address(source)), int(source_port)),
                         (str(ipaddress.ip_address(destination)), int(destination_port)))))


def metadata_tcp_key(key):
    match = re.fullmatch(r'(?:tcp|ssli)_(.+):(\d+)-(?:tcp_|ssli_)?(.+):(\d+)', key)
    if not match:
        return None
    source, sport, destination, dport = match.groups()
    return flow_key(source.strip('[]'), sport, destination.strip('[]'), dport)


def records(path):
    with path.open('rb') as source:
        endian = None
        interfaces = []
        while header := source.read(12):
            if len(header) != 12:
                raise ValueError('truncated block header')
            if header[:4] == b'\x0a\x0d\x0d\x0a':
                interfaces = []
                endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(header[8:12])
            if endian is None:
                raise ValueError('missing or invalid section header')
            kind, length = struct.unpack_from(endian + 'II', header)
            if length < 12 or length % 4 or length > 16 * 1024 * 1024:
                raise ValueError('invalid or oversized block')
            block = header + source.read(length - 12)
            if len(block) != length or struct.unpack_from(endian + 'I', block, length - 4)[0] != length:
                raise ValueError('truncated block or mismatched trailer')
            if kind == 1:
                interfaces.append(struct.unpack_from(endian + 'H', block, 8)[0])
            if kind == 6:
                interface, _, _, captured, _ = struct.unpack_from(endian + 'IIIII', block, 8)
                if interface >= len(interfaces) or captured > length - 32:
                    raise ValueError('invalid packet interface or captured length')
                # Synthetic Smithproxy TCP uses Linux cooked v1 framing.
                if interfaces[interface] == 113:
                    packet = block[28:28 + captured][16:]
                    if packet and packet[0] >> 4 == 4 and len(packet) >= 40 and packet[9] == 6:
                        start = (packet[0] & 15) * 4
                        src, dst = packet[12:16], packet[16:20]
                    elif packet and packet[0] >> 4 == 6 and len(packet) >= 60 and packet[6] == 6:
                        start = 40
                        src, dst = packet[8:24], packet[24:40]
                    else:
                        continue
                    if start < 20 or len(packet) < start + 20:
                        raise ValueError('truncated TCP header')
                    sport, dport = struct.unpack_from('!HH', packet, start)
                    yield '_TCP', dict(key=flow_key(src, sport, dst, dport), flags=packet[start + 13])
                continue
            if kind not in (0xBAD, 0x40000BAD):
                continue
            if length < 16:
                raise ValueError('short custom block')
            if struct.unpack_from(endian + 'I', block, 8)[0] != 67005:
                continue
            if length < 28:
                raise ValueError('short Smithproxy envelope')
            pen, namespace, entry_type, version, size = struct.unpack_from(endian + 'I4sHHI', block, 8)
            if length != 28 + ((size + 3) & ~3) or any(block[24 + size:-4]):
                raise ValueError('invalid payload length or nonzero padding')
            namespace = namespace.decode('ascii')
            if namespace not in ('SXME', 'SXST', 'SXTL', 'SXPP'):
                continue
            if entry_type != 1 or version != (2 if namespace == 'SXPP' else 1):
                raise ValueError('unsupported metadata contract')
            payload = block[24:24 + size].decode('utf-8')
            if namespace == 'SXPP':
                rows = list(csv.reader(io.StringIO(payload), strict=True))
                if len(rows) != 1 or len(rows[0]) != 13:
                    raise ValueError('invalid SXPP row')
                row = rows[0]
                payload = dict(session_id=row[3], proxy_session_key=row[4], seq=int(row[5]),
                               side=row[6], event=row[10], delta_us=int(row[2]))
                if payload['side'] not in ('L', 'R', 'P') or payload['delta_us'] < 0:
                    raise ValueError('invalid event side or delta')
            else:
                payload = json.loads(payload)
                schema = {'SXME': 'metadata', 'SXST': 'statistics', 'SXTL': 'tls'}[namespace]
                if payload.get('schema') != 'smithproxy.' + schema + '.v1':
                    raise ValueError('unexpected JSON schema')
            if not payload.get('session_id') or not payload.get('proxy_session_key'):
                raise ValueError('missing correlation identity')
            yield namespace, payload


def validate(paths, origin_certificate=None):
    counts = collections.Counter()
    session_keys = {}
    sessions = collections.defaultdict(lambda: collections.defaultdict(list))
    for path in paths:
        tcp_stages = {}
        early_metadata = set()
        for namespace, payload in records(path):
            if namespace == '_TCP':
                key, flags = payload['key'], payload['flags']
                stage = tcp_stages.get(key, 0)
                if flags & 2 and not flags & 16:
                    if key in early_metadata:
                        raise ValueError('metadata precedes synthetic TCP handshake')
                    tcp_stages[key] = 1
                elif flags & 2 and flags & 16:
                    if stage != 1:
                        raise ValueError('SYN/ACK without preceding SYN')
                    tcp_stages[key] = 2
                elif flags & 16 and stage == 2:
                    tcp_stages[key] = 3
                continue
            key = metadata_tcp_key(payload['proxy_session_key'])
            if key is not None:
                if key not in tcp_stages:
                    early_metadata.add(key)
                elif tcp_stages[key] != 3:
                    raise ValueError('metadata interrupts synthetic TCP handshake')
            counts[namespace] += 1
            identity = payload['session_id'], payload['proxy_session_key']
            if session_keys.setdefault(identity[0], identity[1]) != identity[1]:
                raise ValueError('session identity reused for a different flow tuple')
            sessions[identity][namespace].append(payload)
    for namespace in ('SXME', 'SXST', 'SXTL', 'SXPP'):
        if not counts[namespace]:
            raise ValueError('missing required ' + namespace)
    tls_verified = 0
    for identity, blocks in sessions.items():
        if 'unknown' in identity[1]:
            raise ValueError('lost flow tuple during teardown')
        if 'SXME' not in blocks:
            raise ValueError('orphan metadata without final SXME: ' + repr(identity))
        if len(blocks['SXME']) != 1:
            raise ValueError('duplicate final SXME: ' + repr(identity))
        seq = [event['seq'] for event in blocks.get('SXPP', [])]
        if len(seq) != len(set(seq)):
            raise ValueError('duplicate event sequence')
        if seq != sorted(seq):
            raise ValueError('protocol events written out of sequence')
        for tls in blocks.get('SXTL', []):
            # Controlled TLS origin in harness/origin.py, not values inferred from SXME.
            if tls['R'].get('sni') != 'origin.runner.lab':
                continue
            if origin_certificate is not None:
                expected_digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                    origin_certificate.read_text())).hexdigest()
                actual_digest = tls['R'].get('peer_certificate', {}).get('sha256', '')
                if actual_digest.lower().replace(':', '').replace(' ', '') != expected_digest:
                    raise ValueError('origin certificate fingerprint mismatch')
                if tls['R'].get('alpn') != 'http/1.1':
                    raise ValueError('unexpected controlled origin ALPN')
                for side, role in (('L', 'server'), ('R', 'client')):
                    leg = tls[side]
                    if leg.get('role') != role or leg.get('state') != 'ready':
                        raise ValueError('incorrect TLS leg role/state')
                    if leg.get('version') not in ('TLSv1.2', 'TLSv1.3') or not leg.get('cipher'):
                        raise ValueError('missing negotiated TLS parameters')
            fingerprints = blocks['SXME'][0].get('ja4', {})
            if not fingerprints.get('client') or not fingerprints.get('server'):
                raise ValueError('controlled TLS flow has missing JA4/JA4S')
            http_fingerprints = fingerprints.get('http')
            if not isinstance(http_fingerprints, list) or not http_fingerprints or not all(
                    isinstance(value, str) and value for value in http_fingerprints):
                raise ValueError('controlled HTTP-over-TLS flow has missing JA4H')
            if not blocks.get('SXPP'):
                raise ValueError('controlled TLS flow has no protocol timeline')
            tls_verified += 1
    if not tls_verified:
        raise ValueError('no controlled origin TLS metadata verified')
    return dict(status='PASS', files=len(paths), blocks=dict(counts),
                sessions=len(sessions), controlled_tls_sessions=tls_verified)


if __name__ == '__main__':
    try:
        paths = sorted(Path(sys.argv[1]).glob(sys.argv[2] + '*.pcapng'))
        report = validate(paths, Path(sys.argv[3]) if len(sys.argv) > 3 else None)
    except (ValueError, KeyError, TypeError, OSError, csv.Error, struct.error) as exc:
        print(json.dumps(dict(status='FAIL', error=str(exc))))
        sys.exit(1)
    print(json.dumps(report, sort_keys=True))
