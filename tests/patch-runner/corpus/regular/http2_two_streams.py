from _common import H2_PREFACE, h2_data, h2_headers, h2_settings, hpack_request, hpack_response, script

PPlayScript = script("http2_two_streams", [
    H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/one")) + h2_headers(3, hpack_request(b"/three")),
    h2_settings() + h2_headers(3, hpack_response()) + h2_data(3, b"three")
    + h2_headers(1, hpack_response()) + h2_data(1, b"one"),
], "cs")
