from _common import H2_PREFACE, h2_headers, h2_settings, hpack_request, script

frame = h2_headers(1, hpack_request(b"/fragmented"))
PPlayScript = script("http2_fragmented_frame", [
    H2_PREFACE + h2_settings(), frame[:2], frame[2:9], frame[9:12], frame[12:],
    h2_settings(),
], "cccccs")
