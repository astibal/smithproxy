from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_ping_wrong_size", [
    H2_PREFACE + h2_settings() + h2_frame(6, 0, 0, b"x") + h2_frame(6, 0, 0, b"y" * 32),
    h2_settings(),
], "cs")
