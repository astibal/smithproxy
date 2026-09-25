from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_window_update_max", [
    H2_PREFACE + h2_settings() + h2_frame(8, 0, 0, b"\x7f\xff\xff\xff"),
    h2_settings() + h2_frame(8, 0, 0, b"\x00\x00\x00\x01"),
], "cs")
