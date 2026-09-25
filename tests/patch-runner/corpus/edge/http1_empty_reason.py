from _common import script

PPlayScript = script("http1_empty_reason", [
    b"GET / HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n",
], "cs")
