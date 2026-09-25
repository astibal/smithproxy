from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_window_update_zero", [
    H2_PREFACE + h2_settings() + h2_frame(8, 0, 0, b"\x00\x00\x00\x00"),
    h2_settings(),
], "cs")
