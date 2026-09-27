from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_rst_wrong_size", [
    H2_PREFACE + h2_settings() + h2_frame(3, 0, 1, b"\x00") + h2_frame(3, 0, 3, b"\x00" * 12),
    h2_settings(),
], "cs")
