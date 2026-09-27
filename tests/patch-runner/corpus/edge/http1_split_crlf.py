from _common import script

PPlayScript = script("http1_split_crlf", [
    b"GET /crlf HTTP/1.1\r", b"\nHost: origin.runner.lab\r", b"\n\r", b"\n",
    b"HTTP/1.1 200 OK\r", b"\nContent-Length: 1\r", b"\n\r", b"\nx",
], "ccccssss")
