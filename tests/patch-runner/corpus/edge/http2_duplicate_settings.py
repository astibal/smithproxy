from _common import H2_PREFACE, h2_settings, script

settings = b"\x00\x01\x00\x00\x10\x00\x00\x01\x00\x00\x20\x00"
PPlayScript = script("http2_duplicate_settings", [H2_PREFACE + h2_settings(settings), h2_settings()], "cs")
