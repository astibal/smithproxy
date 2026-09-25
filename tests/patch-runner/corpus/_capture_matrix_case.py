"""Deterministic cross-format payload matrix for PCAPNG and GRE verification."""
import os

from _common import H2_PREFACE, dns_query, h2_data, h2_frame, h2_headers, h2_settings, hpack_request, hpack_response, script


index = int(os.environ["PPLAY_CAPTURE_INDEX"])
client_marker = f"CMX{index:02d}C".encode()
server_marker = f"CMX{index:02d}S".encode()
family = index % 10
variant = index // 10


def tcp_case():
    if family == 0:
        request = b"GET /capture/" + client_marker + b" HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Matrix: " + client_marker + b"\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(server_marker)).encode() + b"\r\n\r\n" + server_marker
        return request, response
    if family == 1:
        body = b'{"marker":"' + client_marker + b'","variant":' + str(variant).encode() + b"}"
        return (b"POST /capture HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
                b"HTTP/1.1 201 Created\r\nX-Matrix: " + server_marker + b"\r\nContent-Length: 0\r\n\r\n")
    if family == 2:
        chunk = client_marker + b"-chunked-" + bytes((65 + variant,))
        request = b"POST /chunks HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n" + f"{len(chunk):x}".encode() + b"\r\n" + chunk + b"\r\n0\r\n\r\n"
        return request, b"HTTP/1.1 204 No Content\r\nX-Matrix: " + server_marker + b"\r\n\r\n"
    if family == 3:
        stream = 1 + 2 * variant
        request = H2_PREFACE + h2_settings() + h2_headers(stream, hpack_request(b"/" + client_marker))
        response = h2_settings(flags=1) + h2_headers(stream, hpack_response(), flags=4) + h2_data(stream, server_marker)
        return request, response
    if family == 4:
        block = hpack_request(b"/continuation/" + client_marker); cut = len(block) // 2
        request = H2_PREFACE + h2_settings() + h2_frame(1, stream_id=1, payload=block[:cut]) + h2_frame(9, flags=5, stream_id=1, payload=block[cut:])
        return request, h2_settings(flags=1) + h2_headers(1, hpack_response(), flags=4) + h2_data(1, server_marker)
    if family == 5:
        request = b"*3\r\n$3\r\nSET\r\n$" + str(len(client_marker)).encode() + b"\r\n" + client_marker + b"\r\n$1\r\n1\r\n"
        return request, b"+" + server_marker + b"\r\n"
    if family == 6:
        return b"EHLO " + client_marker + b"\r\nNOOP\r\nQUIT\r\n", b"250-" + server_marker + b"\r\n250 OK\r\n221 Bye\r\n"
    if family == 7:
        frame = b"\x82" + bytes((len(client_marker),)) + client_marker
        return b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Matrix: " + client_marker + b"\r\n\r\n" + frame, b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nX-Matrix: " + server_marker + b"\r\n\r\n"
    if family == 8:
        request = len(client_marker).to_bytes(2, "big") + b"\x00\xff" + client_marker + bytes(range(variant * 8, variant * 8 + 8))
        return request, len(server_marker).to_bytes(2, "big") + b"\xff\x00" + server_marker[::-1] + server_marker
    request = dns_query(f"{client_marker.decode().lower()}.capture.test", ident=0xc000 + index)
    return request + client_marker, request[:2] + b"\x81\x83" + b"\x00" * 8 + server_marker


def udp_case():
    if family in (0, 1, 2):
        request = dns_query(f"{client_marker.decode().lower()}.capture.test", qtype=(1, 16, 28)[family], ident=0xd000 + index)
        return request + client_marker, request[:2] + b"\x81\x83" + b"\x00" * 8 + server_marker
    if family in (3, 4):
        return b"<134>1 2026-09-24T00:00:00Z host app - id - " + client_marker, b"ack:" + server_marker
    if family in (5, 6):
        txid = (client_marker + b"000000000000")[:12]
        response_txid = (server_marker + b"000000000000")[:12]
        return b"\x00\x01\x00\x00\x21\x12\xa4\x42" + txid + client_marker, b"\x01\x01\x00\x00\x21\x12\xa4\x42" + response_txid + server_marker
    if family in (7, 8):
        return b"\xc3\x00\x00\x01" + client_marker + bytes((variant,)), b"\x40\x00\x00\x01" + server_marker + bytes((variant,))
    return b"\x30" + bytes((len(client_marker),)) + client_marker, b"\x30" + bytes((len(server_marker),)) + server_marker


packets = tcp_case() if index < 22 else udp_case()
PPlayScript = script(f"capture-matrix-{index:02d}", list(packets), "cs")
