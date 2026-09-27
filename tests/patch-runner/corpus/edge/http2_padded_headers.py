from _common import H2_PREFACE, h2_frame, h2_settings, hpack_request, hpack_response, script

block = hpack_request(b"/padded")
PPlayScript = script("http2_padded_headers", [
    H2_PREFACE + h2_settings() + h2_frame(1, 0x0D, 1, b"\x04" + block + b"\x00" * 4),
    h2_settings() + h2_frame(1, 0x05, 1, hpack_response()),
], "cs")
