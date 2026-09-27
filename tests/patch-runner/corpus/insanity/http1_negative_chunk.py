from _common import script

PPlayScript = script("http1_negative_chunk", [b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nX\r\n0\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"], "cs")
