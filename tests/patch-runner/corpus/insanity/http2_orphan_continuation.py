from _common import H2_PREFACE, h2_frame, h2_settings, script

PPlayScript = script("http2_orphan_continuation", [
    H2_PREFACE + h2_settings() + h2_frame(9, 4, 1, b"\x82\x86\x84"),
    h2_settings(),
], "cs")
