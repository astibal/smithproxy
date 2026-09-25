from _common import H2_PREFACE, h2_settings, script

# A maximum 24-bit declared length with no corresponding payload.
broken = b"\xff\xff\xff\x00\x00\x00\x00\x00\x01"
PPlayScript = script("http2_length_ffffff", [H2_PREFACE + h2_settings() + broken, h2_settings()], "cs")
