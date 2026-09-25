"""Shared helpers and hard safety limits for pplay parser fixtures."""

MAX_FLOW_BYTES = 256 * 1024
MAX_MESSAGES = 256
DEFAULT_PORT = 18080

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2_frame(frame_type, flags=0, stream_id=0, payload=b""):
    payload = bytes(payload)
    if len(payload) > 0xFFFFFF:
        raise ValueError("HTTP/2 frame payload is too large")
    if not 0 <= stream_id <= 0xFFFFFFFF:
        raise ValueError("HTTP/2 stream id does not fit into four bytes")
    return (
        len(payload).to_bytes(3, "big")
        + bytes((frame_type & 0xFF, flags & 0xFF))
        + stream_id.to_bytes(4, "big")
        + payload
    )


def h2_settings(payload=b"", flags=0, stream_id=0):
    return h2_frame(4, flags, stream_id, payload)


def h2_headers(stream_id, block, flags=0x05):
    return h2_frame(1, flags, stream_id, block)


def h2_data(stream_id, data, flags=0x01):
    return h2_frame(0, flags, stream_id, data)


def hpack_request(path=b"/", authority=b"origin.runner.lab"):
    # Indexed :method GET and :scheme http, then literal :authority and :path.
    if len(path) > 126 or len(authority) > 126:
        raise ValueError("helper intentionally supports only short HPACK literals")
    return b"\x82\x86\x01" + bytes((len(authority),)) + authority + b"\x04" + bytes((len(path),)) + path


def hpack_response(status=200):
    indexed = {200: b"\x88", 204: b"\x89", 206: b"\x8a", 304: b"\x8b", 400: b"\x8c", 404: b"\x8d", 500: b"\x8e"}
    return indexed[status]


def dns_name(name):
    labels = name.rstrip(".").split(".") if name.rstrip(".") else []
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise ValueError("DNS label length must be 1..63")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def dns_query(name="example.test", qtype=1, ident=0x1234, flags=0x0100):
    return (
        ident.to_bytes(2, "big") + flags.to_bytes(2, "big")
        + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        + dns_name(name) + qtype.to_bytes(2, "big") + b"\x00\x01"
    )


def dns_answer_a(name="example.test", address=b"\xc0\x00\x02\x01", ident=0x1234):
    question = dns_name(name) + b"\x00\x01\x00\x01"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(address)
    return ident.to_bytes(2, "big") + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer


def script(name, packets, roles, port=DEFAULT_PORT):
    packets = [bytes(packet) for packet in packets]
    roles = list(roles)
    if len(packets) != len(roles):
        raise ValueError(f"{name}: packet and role counts differ")
    if not packets:
        raise ValueError(f"{name}: empty conversation")
    if len(packets) > MAX_MESSAGES:
        raise ValueError(f"{name}: too many messages")
    if sum(map(len, packets)) > MAX_FLOW_BYTES:
        raise ValueError(f"{name}: flow exceeds {MAX_FLOW_BYTES} bytes")
    if any(role not in ("client", "server", "c", "s") for role in roles):
        raise ValueError(f"{name}: invalid role")

    normalized = ["client" if role in ("client", "c") else "server" for role in roles]

    class PPlayScript:
        case_name = name

        def __init__(self, pplay, args=None):
            self.pplay = pplay
            self.args = args
            self.server_port = port
            self.packets = list(packets)
            self.origins = {"client": [], "server": []}
            for index, role in enumerate(normalized):
                self.origins[role].append(index)

            # The current pplay loader reads these even for plaintext tests.
            self.ssl_cert = None
            self.ssl_key = None
            self.ssl_ca_cert = None
            self.ssl_ca_key = None

        def before_send(self, role, index, data):
            return None

        def after_received(self, role, index, data):
            return None

    return PPlayScript
