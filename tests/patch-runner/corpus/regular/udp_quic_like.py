from _common import script

initial = b"\xc3\x00\x00\x00\x01\x08client01\x08server01\x00\x40\x10" + bytes(range(32))
retry = b"\xf0\x00\x00\x00\x01\x08server01\x08client01" + b"retry-token"
PPlayScript = script("udp_quic_like", [initial, retry], "cs")
