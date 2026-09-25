from _common import script

PPlayScript = script("http1_duplicate_headers", [
    b"GET /duplicates HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Value: one\r\nX-Value: two\r\nX-Value: three\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n",
], "cs")
