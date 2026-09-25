from _common import script

PPlayScript = script("http1_options", [
    b"OPTIONS * HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nAllow: GET, HEAD, OPTIONS, POST\r\nContent-Length: 0\r\n\r\n",
], "cs")
