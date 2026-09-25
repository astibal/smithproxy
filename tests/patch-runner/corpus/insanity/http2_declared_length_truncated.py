from _common import H2_PREFACE, h2_settings, script

# Declares 65535 payload bytes but supplies only three.
broken = b"\x00\xff\xff\x00\x00\x00\x00\x00\x01abc"
PPlayScript = script("http2_declared_length_truncated", [
    H2_PREFACE + h2_settings() + broken,
    h2_settings(),
], "cs")
