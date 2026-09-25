from _common import H2_PREFACE, h2_data, h2_headers, h2_settings, hpack_request, hpack_response, script

PPlayScript = script("http2_zero_length_data", [
    H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/empty"), flags=0x04) + h2_data(1, b""),
    h2_settings() + h2_headers(1, hpack_response(), flags=0x04) + h2_data(1, b""),
], "cs")
