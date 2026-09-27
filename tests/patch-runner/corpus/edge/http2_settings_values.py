from _common import H2_PREFACE, h2_settings, script

settings = b"\x00\x01\x00\x00\x10\x00\x00\x03\x00\x00\x00\x64\x00\x04\x00\x00\xff\xff\x00\x05\x00\x00\x40\x00"
PPlayScript = script("http2_settings_values", [H2_PREFACE + h2_settings(settings), h2_settings(settings) + h2_settings(flags=1)], "cs")
