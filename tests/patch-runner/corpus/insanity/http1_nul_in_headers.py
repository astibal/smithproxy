from _common import script

PPlayScript = script("http1_nul_in_headers", [
    b"GET /nul HTTP/1.1\r\nHost: origin.runner.lab\x00.evil.test\r\nX-Nul: before\x00after\r\n\r\n",
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
], "cs")
