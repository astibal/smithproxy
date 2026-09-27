from _common import script

PPlayScript = script("http1_chunk_extensions", [
    b"GET /chunks HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n"
    b"4;name=first\r\ndata\r\n0\r\nX-Checksum: 1234\r\n\r\n",
], "cs")
