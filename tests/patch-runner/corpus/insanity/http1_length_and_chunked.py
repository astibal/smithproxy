from _common import script

PPlayScript = script("http1_length_and_chunked", [
    b"POST /ambiguous HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"4\r\ntest\r\n0\r\n\r\n",
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
], "cs")
