from _common import script

PPlayScript = script("http1_chunked_response", [
    b"GET /stream HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"4\r\none\n\r\n4\r\ntwo\n\r\n0\r\n\r\n",
], "cs")
