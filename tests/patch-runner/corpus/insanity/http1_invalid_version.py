from _common import script

PPlayScript = script("http1_invalid_version", [b"GET / HTTP/9.9\r\nHost: x\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs")
