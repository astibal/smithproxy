from _common import script

value = b"a" * 8192
PPlayScript = script("http1_large_header", [
    b"GET /large-header HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Large: " + value + b"\r\n\r\n",
    b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n",
], "cs")
