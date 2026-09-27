from _common import H2_PREFACE, h2_headers, h2_frame, h2_settings, hpack_request, script

PPlayScript = script("http2_rst_stream", [
    H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/cancel"), flags=0x04) + h2_frame(3, 0, 1, b"\x00\x00\x00\x08"),
    h2_settings(),
], "cs")
