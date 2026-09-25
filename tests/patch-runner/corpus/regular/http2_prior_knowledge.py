from _common import H2_PREFACE, h2_data, h2_headers, h2_settings, hpack_request, hpack_response, script

PPlayScript = script("http2_prior_knowledge", [
    H2_PREFACE + h2_settings() + h2_headers(1, hpack_request(b"/hello")),
    h2_settings() + h2_settings(flags=1) + h2_headers(1, hpack_response()) + h2_data(1, b"hello\n"),
], "cs")
