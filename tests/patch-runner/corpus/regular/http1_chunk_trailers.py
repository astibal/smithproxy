from _common import script

PPlayScript = script("http1_chunk_trailers", [
    b"POST /digest HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\nTrailer: Digest\r\n\r\n4\r\ndata\r\n0\r\nDigest: sha-256=:YWJjZA==:\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
], "cs")
