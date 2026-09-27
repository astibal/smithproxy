from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_unknown_frame", [
    H2_PREFACE + h2_settings() + h2_frame(0xFA, 0xA5, 0, b"unknown-but-bounded"),
    h2_settings() + h2_frame(0xFB, 0, 1, b"ignored"),
], "cs")
