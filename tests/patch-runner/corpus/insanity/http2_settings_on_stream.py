from _common import H2_PREFACE, h2_settings, script

PPlayScript = script("http2_settings_on_stream", [
    H2_PREFACE + h2_settings(stream_id=3, payload=b"\x00\x01\x00\x00\x10\x00"),
    h2_settings(),
], "cs")
