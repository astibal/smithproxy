from _common import H2_PREFACE, h2_frame, h2_settings, script

tiny = b"".join(h2_frame(0xF0 + (i % 16), i & 0xFF, i * 2 + 1, bytes((i,))) for i in range(64))
PPlayScript = script("http2_many_tiny_frames", [
    H2_PREFACE + h2_settings() + tiny,
    h2_settings(),
], "cs")
