from _common import script

PPlayScript = script("http1_header_without_colon", [b"GET / HTTP/1.1\r\nHost: x\r\nthis is not a header\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs")
