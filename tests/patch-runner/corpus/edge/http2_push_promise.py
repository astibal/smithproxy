from _common import H2_PREFACE, h2_frame, h2_headers, h2_settings, hpack_request, hpack_response, script

promise = b"\x00\x00\x00\x02" + hpack_request(b"/style.css")
PPlayScript = script("http2_push_promise", [
    H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/index")),
    h2_settings() + h2_frame(5, 4, 1, promise) + h2_headers(1, hpack_response()),
], "cs")
