from _common import script

PPlayScript = script("udp_quic_truncated_initial", [
    b"\xc3\xff\xff\xff\xff\x14short-cid",
    b"\xf0\x00\x00",
], "cs")
