from _common import script

PPlayScript = script("http1_empty_header_value", [
    b"GET /empty HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Empty:\r\nX-Space: \r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Empty:\r\n\r\n",
], "cs")
