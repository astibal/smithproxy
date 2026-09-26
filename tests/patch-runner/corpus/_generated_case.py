"""Parametric deterministic corpus: a base matrix plus 100 extended cases."""
import os

from _common import H2_PREFACE, dns_answer_a, dns_query, h2_data, h2_frame, h2_headers, h2_settings, hpack_request, hpack_response, script


category = os.environ["PPLAY_GENERATED_CATEGORY"]
index = int(os.environ["PPLAY_GENERATED_INDEX"])
family = index % 10
variant = index // 10
tag = f"{category}-{index:03d}".encode()


def regular_case():
    if family == 0:
        return [b"GET /matrix/" + tag + b"?v=" + str(variant).encode() + b" HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Matrix: " + tag + b"\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(tag)).encode() + b"\r\n\r\n" + tag], "cs"
    if family == 1:
        body = b'{"case":"' + tag + b'","n":' + str(variant).encode() + b"}"
        return [b"POST /matrix HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body, b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 2:
        body = tag + b"-chunk"
        return [b"POST /chunks HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n" + f"{len(body):x}".encode() + b"\r\n" + body + b"\r\n0\r\n\r\n", b"HTTP/1.1 204 No Content\r\n\r\n"], "cs"
    if family == 3:
        return [H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/" + tag)), h2_settings() + h2_headers(1, hpack_response())], "cs"
    if family == 4:
        return [b"*3\r\n$3\r\nSET\r\n$" + str(len(tag)).encode() + b"\r\n" + tag + b"\r\n$1\r\n" + str(variant).encode() + b"\r\n", b"+OK\r\n", b"*2\r\n$3\r\nGET\r\n$" + str(len(tag)).encode() + b"\r\n" + tag + b"\r\n", b"$1\r\n" + str(variant).encode() + b"\r\n"], "cscs"
    if family == 5:
        return [b"220 matrix ESMTP\r\n", b"EHLO " + tag + b"\r\n", b"250-matrix\r\n250 PIPELINING\r\n", b"NOOP\r\nQUIT\r\n", b"250 OK\r\n221 Bye\r\n"], "scscs"
    if family == 6:
        payload = bytes(range(variant, variant + 16)) + tag
        return [len(payload).to_bytes(2, "big") + payload, b"ACK" + tag], "cs"
    if family == 7:
        query = dns_query(f"r{index}.matrix.test", qtype=(1, 16, 28)[variant % 3], ident=0x6000 + index)
        return [query, query[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:]], "cs"
    if family == 8:
        msg = b"<134>1 2026-09-22T00:00:00Z matrix app - ID" + str(index).encode() + b" - " + tag
        return [msg, b"ack:" + tag], "cs"
    request = b"\x00\x01\x00\x00" + index.to_bytes(4, "big") + tag
    return [request, b"\x01\x01\x00\x00" + index.to_bytes(4, "big") + tag], "cs"


def edge_case():
    if family == 0:
        value = b"x" * (128 + variant * 97)
        return [b"GET /edge/" + tag + b" HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Long: " + value + b"\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 1:
        return [b"GET /split/" + tag[:5], tag[5:] + b" HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"], "ccs"
    if family == 2:
        size = 1 + variant
        body = bytes((65 + variant,)) * size
        return [b"POST /tiny HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n" + f"{size:x};v={variant}".encode() + b"\r\n" + body + b"\r\n0\r\nX-End: yes\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 3:
        block = hpack_request(b"/" + tag)
        cut = 1 + variant % (len(block) - 1)
        return [H2_PREFACE + h2_settings() + h2_headers(1, block[:cut], flags=0x01) + bytes((0, 0, len(block) - cut, 9, 4, 0, 0, 0, 1)) + block[cut:], h2_settings()], "cs"
    if family == 4:
        return [b"*3\r\n$4\r\nMGET\r\n$0\r\n\r\n$" + str(len(tag)).encode() + b"\r\n" + tag + b"\r\n", b"*2\r\n$-1\r\n$0\r\n\r\n"], "cs"
    if family == 5:
        return [b"220 matrix\r\n", b"EHLO " + tag + b"\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n", b"250-hi\r\n250 PIPELINING\r\n250 OK\r\n250 OK\r\n"], "scs"
    if family == 6:
        return [b"\x00" * variant + tag + b"\xff" * (9 - variant), b"\xff" * variant + tag[::-1]], "cs"
    if family == 7:
        label = "x" * (54 + variant)
        query = dns_query(label + ".test", ident=0x7000 + index)
        return [query, query[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:]], "cs"
    if family == 8:
        return [b"<" + str(variant).encode() + b">" + tag + b"\x00\xff", b"ok"], "cs"
    return [b"\x00\x01" + (variant * 257).to_bytes(2, "big") + tag, b"\x01\x01" + tag], "cs"


def insanity_case():
    if family == 0:
        return [b"G" + b"E" * (32 + variant * 64) + b"T / HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 1:
        return [b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(10**(variant + 6)).encode() + b"\r\n\r\n" + tag, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 2:
        return [b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + b"f" * (8 + variant) + b"\r\n" + tag, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 3:
        bad = bytes((0xff, 0xff, variant, 1, variant)) + tag
        return [H2_PREFACE + h2_settings() + h2_headers(1 + 2 * variant, bad), h2_settings()], "cs"
    if family == 4:
        return [b"*" + str(-(variant + 2)).encode() + b"\r\n$" + str(2**(20 + variant)).encode() + b"\r\n" + tag, b"-ERR malformed\r\n"], "cs"
    if family == 5:
        return [b"\x16\x03" + bytes((variant, 0xff, 0xff)) + tag, b"\x15\x03\x03\x00\x02\x02\x32"], "cs"
    if family == 6:
        return [bytes((5, 1, variant)), bytes((5, 0)), bytes((5, 1, 0, 0xf0 + variant)) + tag, bytes((5, 8, 0, 1, 0, 0, 0, 0, 0, 0))], "cscs"
    if family == 7:
        query = bytearray(dns_query(f"i{index}.test", ident=0x8000 + index)); query[4:6] = (1000 + variant).to_bytes(2, "big")
        return [bytes(query), bytes(query[:2]) + b"\x81\x81\x00\x00\x00\x00\x00\x00\x00\x00"], "cs"
    if family == 8:
        return [bytes((0x30 | variant, 0xff, 0xff, 0xff, 0x7f)) + tag, b"\xd0\x00"], "cs"
    return [b"\xc0" + bytes((variant,)) + b"\x00\x00\x00\x00" + tag, b"\x00" * (1 + variant)], "cs"


def extended_regular_case():
    extra, family = index - 100, (index - 100) % 10
    variant = extra // 10
    if family == 0:
        req = b"".join(b"GET /pipeline/" + tag + b"/" + str(i).encode() + b" HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n" for i in range(2 + variant))
        rsp = b"".join(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n" + bytes((65 + i,)) for i in range(2 + variant))
        return [req, rsp], "cs"
    if family == 1:
        body = (tag + b"|") * (2 + variant); cut = len(body) // 2
        head = b"POST /split-body HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n"
        return [head + body[:cut], body[cut:], b"HTTP/1.1 204 No Content\r\n\r\n"], "ccs"
    if family == 2:
        chunks = [tag[:3], b"x" * (variant + 1), tag[3:]]
        encoded = b"".join(f"{len(chunk):x}".encode() + b"\r\n" + chunk + b"\r\n" for chunk in chunks)
        return [b"POST /chunks HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n" + encoded + b"0\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 3:
        streams = range(1, 4 + 2 * variant, 2)
        client = H2_PREFACE + h2_settings() + b"".join(h2_headers(s, hpack_request(b"/multi/" + str(s).encode())) for s in streams)
        server = h2_settings(flags=1) + b"".join(h2_headers(s, hpack_response()) + h2_data(s, tag) for s in streams)
        return [client, server], "cs"
    if family == 4:
        return [b"GET /ws HTTP/1.1\r\nHost: origin.runner.lab\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", b"\x81" + bytes((len(tag),)) + tag, b"\x81\x02ok"], "cscs"
    if family == 5:
        return [b"* OK IMAP4 ready\r\n", b"a1 CAPABILITY\r\na2 NOOP\r\n", b"* CAPABILITY IMAP4rev1 IDLE\r\na1 OK done\r\na2 OK done\r\n", b"a3 LOGOUT\r\n", b"* BYE\r\na3 OK done\r\n"], "scscs"
    if family == 6:
        payload = b"\x00\xff" + bytes(range(16 * variant, 16 * variant + 16)) + tag
        return [len(payload).to_bytes(4, "big") + payload, b"\x00\x00\x00\x02OK"], "cs"
    if family == 7:
        name = f"extra{index}.matrix.test"
        return [dns_query(name, ident=0x9000 + extra), dns_answer_a(name, ident=0x9000 + extra)], "cs"
    if family == 8:
        return [b"\x23" + b"\x00" * 39 + extra.to_bytes(8, "big"), b"\x24\x02" + b"\x00" * 38 + extra.to_bytes(8, "big")], "cs"
    txid = (tag + b"000000000000")[0:12]
    return [b"\x00\x01\x00\x00\x21\x12\xa4\x42" + txid, b"\x01\x01\x00\x00\x21\x12\xa4\x42" + txid], "cs"


def extended_edge_case():
    extra, family = index - 100, (index - 100) % 10
    variant = extra // 10
    if family == 0:
        return [b"GE", b"T /boundary/" + tag, b" HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"], "cccs"
    if family == 1:
        return [b"GET /headers HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Split", b": " + tag + b"\r", b"\n\r\n", b"HTTP/1.1 204 No Content\r\n\r\n"], "cccs"
    if family == 2:
        chunks = b"".join(b"1\r\n" + bytes((65 + i,)) + b"\r\n" for i in range(1 + variant * 3))
        return [b"POST /byte-chunks HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks + b"0\r\nX-Trailer: yes\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 3:
        frame = h2_headers(1, hpack_request(b"/fragmented/" + tag)); cuts = (5, 10 + variant, len(frame) - 2)
        return [H2_PREFACE + h2_settings() + frame[:cuts[0]], frame[cuts[0]:cuts[1]], frame[cuts[1]:cuts[2]], frame[cuts[2]:], h2_settings(flags=1)], "ccccs"
    if family == 4:
        controls = h2_frame(6, payload=extra.to_bytes(8, "big")) + h2_frame(8, payload=(1 + variant).to_bytes(4, "big")) + h2_frame(3, stream_id=1, payload=b"\x00\x00\x00\x08")
        return [H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/control"), flags=4) + controls, h2_settings(flags=1)], "cs"
    if family == 5:
        return [b"POST /continue HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n", b"HTTP/1.1 100 Continue\r\n\r\n", bytes((65 + variant,)), b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"], "cscs"
    if family == 6:
        payload = tag.center(63 + variant * 64, b"\x00")
        return [payload[:1], payload[1:-1], payload[-1:], b"ACK"], "cccs"
    if family == 7:
        label = (("e" * (60 + variant)) + str(extra))[:63]; query = dns_query(label + ".edge.test", ident=0xa000 + extra)
        return [query, query[:2] + b"\x81\x83\x00\x01" + b"\x00" * 6 + query[12:]], "cs"
    if family == 8:
        return [b"<191>1 2026-09-24T23:59:59Z host app - id [x k=\"" + tag + b"\"] " + b"x" * (128 * (variant + 1)), b"ok"], "cs"
    return [b"\xc3\x00\x00\x01" + tag + b"\x00" * variant, b"\x40" + tag[::-1]], "cs"


def extended_insanity_case():
    extra, family = index - 100, (index - 100) % 10
    variant = extra // 10
    if family == 0:
        return [b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: " + str(variant + 1).encode() + b"\r\n\r\n" + tag, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 1:
        return [b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + b"0" * (16 + variant * 8) + b"1\r\nX\r\n0\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 2:
        return [b"GET / HTTP/1.1\r\nHost: x\r\nX" + bytes((0, 10, 13, 127 + variant)) + b": y\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs"
    if family == 3:
        header = (32 + variant * 1024).to_bytes(3, "big") + b"\x01\x05\x00\x00\x00\x01"
        return [H2_PREFACE + h2_settings() + header + tag, h2_frame(7, payload=b"\x00" * 8)], "cs"
    if family == 4:
        frames = b"".join(h2_frame(9, flags=i & 4, stream_id=1 + 2 * (i & 1), payload=bytes((0xff, i))) for i in range(4 + variant))
        return [H2_PREFACE + h2_settings() + frames, h2_settings(flags=1)], "cs"
    if family == 5:
        return [b"\x16\x03\x03" + (0xffff - variant).to_bytes(2, "big") + b"\x01\x00\x00" + bytes((variant,)) + tag, b"\x15\x03\x03\x00\x02\x02\x32"], "cs"
    if family == 6:
        return [b"*2\r\n$" + str(0x7fffffff - variant).encode() + b"\r\n" + tag + b"\r\n$-3\r\n", b"-ERR malformed\r\n"], "cs"
    if family == 7:
        query = bytearray(dns_query(f"bad{extra}.test", ident=0xb000 + extra)); query[-4:-2] = b"\xff\xff"
        return [bytes(query[:len(query) - variant]), bytes(query[:2]) + b"\x81\x81" + b"\x00" * 8], "cs"
    if family == 8:
        return [b"\x00\x01" + (0xffff - variant).to_bytes(2, "big") + b"\x21\x12\xa4\x42" + tag, b"\x01\x11\x00\x00" + b"\x00" * 16], "cs"
    return [b"\xc0" + bytes((0xff - variant,)) + tag + b"\x00" * (1 + variant), b"\x00\x00\xff\xff"], "cs"


def http2_case():
    case = index - 200
    family, variant = divmod(case, 10)
    marker = f"h2-{case:03d}".encode()
    if family == 0:
        streams = list(range(1, 2 * (variant + 2), 2))
        client = H2_PREFACE + h2_settings() + b"".join(h2_headers(s, hpack_request(b"/mux/" + marker + b"/" + str(s).encode())) for s in streams)
        server = h2_settings(flags=1) + b"".join(h2_headers(s, hpack_response(), flags=4) + h2_data(s, marker + bytes((s,))) for s in reversed(streams))
        return [client, server], "cs"
    if family == 1:
        pieces = [marker[i:i + 1 + variant % 3] for i in range(0, len(marker), 1 + variant % 3)]
        first = H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/data/" + marker), flags=4)
        data = [h2_data(1, piece, flags=1 if i == len(pieces) - 1 else 0) for i, piece in enumerate(pieces)]
        return [first] + data + [h2_settings(flags=1) + h2_headers(1, hpack_response())], "c" * (1 + len(data)) + "s"
    if family == 2:
        setting_id = 1 + variant % 6
        settings = setting_id.to_bytes(2, "big") + (variant * 1024 + 1).to_bytes(4, "big")
        controls = h2_frame(6, payload=variant.to_bytes(8, "big")) + h2_frame(8, payload=(variant + 1).to_bytes(4, "big"))
        return [H2_PREFACE + h2_settings(settings) + controls, h2_settings(flags=1) + h2_frame(6, flags=1, payload=variant.to_bytes(8, "big"))], "cs"
    if family == 3:
        name = b"x-dynamic-" + str(variant).encode(); value = marker + b"-value"
        literal = b"\x40" + bytes((len(name),)) + name + bytes((len(value),)) + value
        return [H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/table") + literal) + h2_headers(3, hpack_request(b"/reuse") + b"\xbe"), h2_settings(flags=1) + h2_headers(1, hpack_response()) + h2_headers(3, hpack_response())], "cs"
    if family == 4:
        block = hpack_request(b"/continuation/" + marker)
        first_cut = 1 + variant % max(1, len(block) - 2); second_cut = min(len(block) - 1, first_cut + 1 + variant % 4)
        frames = h2_frame(1, flags=1, stream_id=1, payload=block[:first_cut]) + h2_frame(9, stream_id=1, payload=block[first_cut:second_cut]) + h2_frame(9, flags=4, stream_id=1, payload=block[second_cut:])
        return [H2_PREFACE + h2_settings() + frames, h2_settings(flags=1) + h2_headers(1, hpack_response())], "cs"
    if family == 5:
        block = hpack_request(b"/padded/" + marker); padding = b"\x00" * variant
        dependency = (0x80000000 | (3 + 2 * variant)).to_bytes(4, "big")
        payload = bytes((variant,)) + dependency + bytes((16 + variant,)) + block + padding
        return [H2_PREFACE + h2_settings() + h2_frame(1, flags=0x2d, stream_id=1, payload=payload), h2_settings(flags=1) + h2_headers(1, hpack_response())], "cs"
    if family == 6:
        stream = 1 + 2 * variant
        open_streams = b"".join(h2_headers(s, hpack_request(b"/life/" + str(s).encode()), flags=4) for s in range(1, stream + 3, 2))
        reset = h2_frame(3, stream_id=stream, payload=(8).to_bytes(4, "big"))
        goaway = h2_frame(7, payload=stream.to_bytes(4, "big") + (0).to_bytes(4, "big") + marker)
        return [H2_PREFACE + h2_settings() + open_streams + reset, h2_settings(flags=1) + goaway], "cs"
    if family == 7:
        malformed = (
            h2_frame(4, stream_id=1, payload=b""),
            h2_frame(6, payload=b"x" * (7 + variant % 3)),
            h2_frame(8, stream_id=1, payload=(0).to_bytes(4, "big")),
            h2_frame(3, stream_id=1, payload=b"x" * variant),
            h2_frame(0, stream_id=0, payload=marker),
        )[variant % 5]
        return [H2_PREFACE + h2_settings() + malformed, h2_frame(7, payload=b"\x00" * 8)], "cs"
    if family == 8:
        block = hpack_request(b"/broken/" + marker); cut = 1 + variant % (len(block) - 1)
        middle = h2_frame(0 if variant % 2 else 9, stream_id=3, payload=b"x")
        frames = h2_frame(1, stream_id=1, payload=block[:cut]) + middle + h2_frame(9, flags=4, stream_id=1, payload=block[cut:])
        return [H2_PREFACE + h2_settings() + frames, h2_frame(7, payload=b"\x00" * 8)], "cs"
    invalid_blocks = (b"\x80", b"\xff", b"\x3f", b"\x20\xff", b"\x40\x7f", b"\x00\x81\xff", b"\xbe", b"\x3f\xff\xff", b"\x40\x01x\x7f", b"\x00")
    return [H2_PREFACE + h2_settings() + h2_headers(1, invalid_blocks[variant]), h2_frame(7, payload=b"\x00" * 8)], "cs"


if index >= 200:
    packets, roles = http2_case()
elif index < 100:
    packets, roles = {"regular": regular_case, "edge": edge_case, "insanity": insanity_case}[category]()
else:
    packets, roles = {"regular": extended_regular_case, "edge": extended_edge_case, "insanity": extended_insanity_case}[category]()
PPlayScript = script(f"generated-{category}-{index:03d}", packets, roles)
