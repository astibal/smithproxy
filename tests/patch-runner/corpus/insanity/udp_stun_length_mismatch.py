from _common import script

cookie = b"\x21\x12\xa4\x42"
PPlayScript = script("udp_stun_length_mismatch", [
    b"\x00\x01\xff\xfc" + cookie + b"bad-stun-tx1",
    b"\x01\x11\x00\x01" + cookie + b"bad-stun-tx1" + b"x",
], "cs")
