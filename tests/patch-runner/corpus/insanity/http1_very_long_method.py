from _common import script

method = b"M" * 4096
PPlayScript = script("http1_very_long_method", [
    method + b" / HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
], "cs")
