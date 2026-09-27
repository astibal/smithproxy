from _common import script

PPlayScript = script("http1_asterisk_target", [
    b"OPTIONS * HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nAllow: GET, HEAD, OPTIONS\r\nContent-Length: 0\r\n\r\n",
], "cs")
