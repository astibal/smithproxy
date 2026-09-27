from _common import H2_PREFACE, h2_headers, h2_settings, script

blocks = [b"\xff", b"\x3f\xff\xff\xff\xff\x7f", b"\x00\x7f", b"\x80"]
PPlayScript = script("http2_invalid_hpack", [
    H2_PREFACE + h2_settings() + b"".join(h2_headers(1 + i * 2, block) for i, block in enumerate(blocks)),
    h2_settings(),
], "cs")
