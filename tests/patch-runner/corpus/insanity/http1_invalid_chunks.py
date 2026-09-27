from _common import script

PPlayScript = script("http1_invalid_chunks", [
    b"POST /bad-chunks HTTP/1.1\r\nHost: origin.runner.lab\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"-1\r\na\r\nGG\r\nb\r\n3\r\nxy\r\n",
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
], "cs")
