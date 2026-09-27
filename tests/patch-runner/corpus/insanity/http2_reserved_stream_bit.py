from _common import H2_PREFACE, h2_headers, h2_settings, hpack_request, script

PPlayScript = script("http2_reserved_stream_bit", [
    H2_PREFACE + h2_settings() + h2_headers(0x80000001, hpack_request(b"/reserved")),
    h2_settings(),
], "cs")
