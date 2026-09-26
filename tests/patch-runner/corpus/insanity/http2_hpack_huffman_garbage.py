from _common import H2_PREFACE, h2_headers, h2_settings, script

# Literal name/value lengths with the Huffman bit set, followed by invalid tails.
blocks = (b"\x00\x85\xff\xff\xff\xff\xff\x81\xff", b"\x40\x81\x00\x8f" + b"\xff" * 15)
PPlayScript = script("http2_hpack_huffman_garbage", [
    H2_PREFACE + h2_settings() + h2_headers(1, blocks[0]) + h2_headers(3, blocks[1]),
    h2_settings(),
], "cs")
