from _common import script

PPlayScript = script("http1_range", [
    b"GET /file.bin HTTP/1.1\r\nHost: origin.runner.lab\r\nRange: bytes=100-199\r\n\r\n",
    b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 100-199/1000\r\nContent-Length: 100\r\n\r\n" + b"R" * 100,
], "cs")
