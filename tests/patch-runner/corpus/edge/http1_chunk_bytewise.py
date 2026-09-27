from _common import script

PPlayScript = script("http1_chunk_bytewise", [
    b"POST /bytewise HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"1", b"\r", b"\n", b"x", b"\r", b"\n", b"0", b"\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
], "cccccccccs")
