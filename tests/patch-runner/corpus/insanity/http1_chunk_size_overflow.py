from _common import script

PPlayScript = script("http1_chunk_size_overflow", [
    b"POST /chunk-overflow HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\r\nx\r\n0\r\n\r\n",
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
], "cs")
