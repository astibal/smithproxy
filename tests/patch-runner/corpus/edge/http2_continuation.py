from _common import H2_PREFACE, h2_frame, h2_settings, hpack_request, hpack_response, script

request = hpack_request(b"/continuation")
PPlayScript = script("http2_continuation", [
    H2_PREFACE + h2_settings() + h2_frame(1, 0x01, 1, request[:5]) + h2_frame(9, 0x04, 1, request[5:]),
    h2_settings() + h2_frame(1, 0x01, 1, hpack_response()),
], "cs")
