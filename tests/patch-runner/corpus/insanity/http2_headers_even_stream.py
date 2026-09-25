from _common import H2_PREFACE, h2_headers, h2_settings, hpack_request, script

PPlayScript = script("http2_headers_even_stream", [H2_PREFACE + h2_settings() + h2_headers(2, hpack_request(b"/even")), h2_settings()], "cs")
