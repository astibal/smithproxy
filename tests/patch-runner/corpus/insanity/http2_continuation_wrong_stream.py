from _common import H2_PREFACE, h2_frame, h2_settings, hpack_request, script

block = hpack_request(b"/wrong-stream")
PPlayScript = script("http2_continuation_wrong_stream", [
    H2_PREFACE + h2_settings() + h2_frame(1, 0, 1, block[:4]) + h2_frame(9, 4, 3, block[4:]),
    h2_settings(),
], "cs")
