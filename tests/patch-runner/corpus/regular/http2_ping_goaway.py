from _common import H2_PREFACE, h2_frame, h2_settings, script

opaque = b"12345678"
PPlayScript = script("http2_ping_goaway", [
    H2_PREFACE + h2_settings() + h2_frame(6, 0, 0, opaque),
    h2_settings() + h2_frame(6, 1, 0, opaque) + h2_frame(7, 0, 0, b"\x00\x00\x00\x00\x00\x00\x00\x00"),
], "cs")
