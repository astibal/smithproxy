from _common import H2_PREFACE, h2_headers, h2_settings, hpack_request, script

PPlayScript = script("http2_headers_stream_zero", [
    H2_PREFACE + h2_settings() + h2_headers(0, hpack_request(b"/zero")),
    h2_settings(),
], "cs")
