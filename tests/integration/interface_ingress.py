#!/usr/bin/env python3
"""Run only in an isolated namespace: unshare -Urn python3 interface_ingress.py.
Checks real veth ingress for TCP packet options and UDP ancillary metadata,
including TPROXY and IPv4 clients accepted by a dual-stack listener.
"""
import os
import socket
import struct
import subprocess
import sys


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stderr}')
    return result.stdout


def idx_from_options(data):
    offset = 0
    while offset + 16 <= len(data):
        length, level, kind = struct.unpack_from('@Qii', data, offset)
        assert 16 <= length <= len(data) - offset
        body = data[offset + 16:offset + length]
        if (level, kind) == (socket.IPPROTO_IP, 8):
            return struct.unpack_from('@I', body)[0]
        if (level, kind) == (socket.IPPROTO_IPV6, 50):
            return struct.unpack_from('@I', body, 16)[0]
        offset += (length + 7) & ~7
    raise AssertionError('missing packet info')


if len(sys.argv) > 1 and sys.argv[1] == 'client':
    print(os.getpid(), flush=True)
    sys.stdin.readline()
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'set', 'client0', 'up')
    run('ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'client0')
    run('ip', '-6', 'addr', 'add', '2001:db8:1::2/64', 'dev', 'client0', 'nodad')
    run('ip', 'route', 'add', 'default', 'via', '192.0.2.1')
    run('ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:1::1')
    print('ready', flush=True)
    for line in sys.stdin:
        family, transport, destination, port = line.split()
        with socket.socket(int(family), int(transport)) as sock:
            sock.settimeout(3)
            sock.connect((destination, int(port)))
            if int(transport) == socket.SOCK_DGRAM:
                sock.send(b'probe')
            else:
                sock.recv(1)
        print('done', flush=True)
    sys.exit(0)

run('ip', 'link', 'set', 'lo', 'up')
client = subprocess.Popen(['unshare', '--net', sys.executable, __file__, 'client'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
try:
    pid = int(client.stdout.readline())
    run('ip', 'link', 'add', 'proxy0', 'type', 'veth', 'peer', 'name', 'client0')
    run('ip', 'link', 'set', 'client0', 'netns', str(pid))
    run('ip', 'link', 'set', 'proxy0', 'up')
    run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'proxy0')
    run('ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'proxy0', 'nodad')
    client.stdin.write('start\n'); client.stdin.flush()
    assert client.stdout.readline().strip() == 'ready'
    run('ip', 'rule', 'add', 'fwmark', '1', 'lookup', '100')
    run('ip', 'route', 'add', 'local', 'default', 'dev', 'lo', 'table', '100')
    run('ip', '-6', 'rule', 'add', 'fwmark', '1', 'lookup', '100')
    run('ip', '-6', 'route', 'add', 'local', 'default', 'dev', 'lo', 'table', '100')
    run('nft', '-f', '-', input='''table inet test {
      chain pre { type filter hook prerouting priority mangle; policy accept;
        ip daddr 198.51.100.10 meta l4proto { tcp, udp } tproxy ip to :18443 meta mark set 1 accept
        ip6 daddr 2001:db8:2::10 meta l4proto { tcp, udp } tproxy ip6 to :18443 meta mark set 1 accept
      }
    }''')
    expected = socket.if_nametoindex('proxy0')
    for family, destination in [(socket.AF_INET, '192.0.2.1'), (socket.AF_INET6, '2001:db8:1::1'),
                                (socket.AF_INET, '198.51.100.10'), (socket.AF_INET6, '2001:db8:2::10')]:
        for transport in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
            # IPv4 uses an IPv6 dual-stack listener, just like the proxy.
            with socket.socket(socket.AF_INET6, transport) as listener:
                listener.settimeout(3)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                listener.setsockopt(socket.IPPROTO_IP, 19, 1)  # IP_TRANSPARENT
                listener.setsockopt(socket.IPPROTO_IPV6, 75, 1)  # IPV6_TRANSPARENT
                listener.setsockopt(socket.IPPROTO_IP, 8, 1)
                listener.setsockopt(socket.IPPROTO_IPV6, 49, 1)
                listener.bind(('::', 18443))
                if transport == socket.SOCK_STREAM:
                    listener.listen()
                client.stdin.write(f'{family} {transport} {destination} 18443\n'); client.stdin.flush()
                if transport == socket.SOCK_STREAM:
                    accepted, _ = listener.accept()
                    with accepted:
                        actual = idx_from_options(accepted.getsockopt(socket.IPPROTO_IPV6, 6, 256))
                        accepted.send(b'x')
                else:
                    _, controls, flags, _ = listener.recvmsg(32, 256)
                    assert not flags & socket.MSG_CTRUNC
                    actual = next(struct.unpack_from('@I', data, 0 if level == socket.IPPROTO_IP else 16)[0]
                                  for level, kind, data in controls
                                  if (level, kind) in [(socket.IPPROTO_IP, 8), (socket.IPPROTO_IPV6, 50)])
                assert actual == expected, (destination, transport, actual, expected)
                assert client.stdout.readline().strip() == 'done'
                print(destination, 'TCP' if transport == socket.SOCK_STREAM else 'UDP', 'ifindex', actual, 'PASS')
finally:
    client.stdin.close()
    try:
        client.wait(timeout=5)
    except subprocess.TimeoutExpired:
        client.kill(); client.wait()
