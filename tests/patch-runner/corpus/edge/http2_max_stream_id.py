from _common import H2_PREFACE, h2_headers, h2_settings, hpack_request, hpack_response, script

stream = 0x7FFFFFFF
PPlayScript = script("http2_max_stream_id", [
    H2_PREFACE + h2_settings() + h2_headers(stream, hpack_request(b"/last")),
    h2_settings() + h2_headers(stream, hpack_response()),
], "cs")
