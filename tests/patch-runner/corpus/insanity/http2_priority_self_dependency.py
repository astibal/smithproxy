from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_priority_self_dependency", [
    H2_PREFACE + h2_settings() + h2_frame(2, 0, 3, b"\x00\x00\x00\x03\x00"),
    h2_settings(),
], "cs")
