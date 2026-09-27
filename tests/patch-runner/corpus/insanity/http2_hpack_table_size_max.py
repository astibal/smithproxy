from _common import H2_PREFACE, h2_headers, h2_settings, script

# HPACK dynamic table size update with a very large encoded value.
PPlayScript = script("http2_hpack_table_size_max", [H2_PREFACE + h2_settings() + h2_headers(1, b"\x3f\xe0\xff\xff\xff\x07"), h2_settings()], "cs")
