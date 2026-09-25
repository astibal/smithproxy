from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_goaway_on_stream", [
    H2_PREFACE + h2_settings() + h2_frame(7, 0, 5, b"\x00" * 8),
    h2_settings(),
], "cs")
