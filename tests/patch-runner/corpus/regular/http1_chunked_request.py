from _common import script

PPlayScript = script("http1_chunked_request", [
    b"POST /upload HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
], "cs")
