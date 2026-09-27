from _common import H2_PREFACE, h2_headers, h2_settings, hpack_response, script


authority = b"origin.runner.lab"

# Indexed :method GET and :scheme http, followed by a literal :authority.
# Deliberately omit :path while retaining enough request state to exercise
# fill_kb() without relying on fragmented HEADERS/CONTINUATION handling.
request_without_path = b"\x82\x86\x01" + bytes((len(authority),)) + authority

PPlayScript = script("http2_missing_path", [
    H2_PREFACE + h2_settings() + h2_headers(1, request_without_path),
    h2_settings() + h2_headers(1, hpack_response()),
], "cs")

