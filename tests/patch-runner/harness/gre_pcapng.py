"""Reconstruct GRE/PCAPNG records independently of the exporting implementation."""
import collections
import pathlib
import shutil
import struct
import subprocess
import tempfile


def restore(source, destination=None):
    source = pathlib.Path(source)
    destination = pathlib.Path(destination) if destination else source.with_suffix('.restored.pcapng')
    # Tshark performs outer IPv4 reassembly, including records larger than MTU.
    # Tshark may drop privileges. Do not make the retained /root lab readable;
    # stage just this test input, then remove the temporary copy automatically.
    with tempfile.TemporaryDirectory(prefix='capture-gre-') as directory:
        staging = pathlib.Path(directory)
        staging.chmod(0o755)
        staged = staging / 'wire.pcap'
        shutil.copyfile(source, staged)
        staged.chmod(0o644)
        result = subprocess.run([
            'tshark', '-r', str(staged), '-o', 'ip.defragment:TRUE',
            '-Y', 'gre.proto == 0x88b5', '-T', 'fields', '-e', 'data.data',
        ], check=True, text=True, capture_output=True)
    records = []
    counts = collections.Counter()
    for line in result.stdout.splitlines():
        payload = bytes.fromhex(line.replace(':', ''))
        offset = 0
        while offset < len(payload):
            if len(payload) - offset < 12:
                raise AssertionError('truncated GRE/PCAPNG block')
            kind, size = struct.unpack_from('<II', payload, offset)
            if size < 12 or size % 4 or offset + size > len(payload):
                raise AssertionError('invalid GRE/PCAPNG block length')
            if struct.unpack_from('<I', payload, offset + size - 4)[0] != size:
                raise AssertionError('mismatched GRE/PCAPNG trailing length')
            records.append(payload[offset:offset + size])
            counts[kind] += 1
            offset += size
    if not counts[6]:
        raise AssertionError('GRE/PCAPNG contains no packet blocks')
    # Record transport has no file preamble. Its interface is Linux cooked v1.
    preamble = struct.pack('<IIIHHqI', 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
    preamble += struct.pack('<IIHHII', 1, 20, 113, 0, 65535, 20)
    destination.write_bytes(preamble + b''.join(records))
    return destination, dict(counts)
