from _common import script

PPlayScript = script("http1_unusual_method", [
    b"PROPFIND /dav/ HTTP/1.1\r\nHost: origin.runner.lab\r\nDepth: 1\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\n\r\n",
], "cs")
