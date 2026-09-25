from _common import script

PPlayScript = script("http1_304_headers", [
    b"GET /cached HTTP/1.1\r\nHost: origin.runner.lab\r\nIf-None-Match: \"abc\"\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\nContent-Length: 999\r\n\r\n",
], "cs")
