from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_priority", [
    H2_PREFACE + h2_settings() + h2_frame(2, 0, 3, b"\x00\x00\x00\x01\xff"),
    h2_settings() + h2_frame(8, 0, 0, b"\x00\x01\x00\x00"),
], "cs")
