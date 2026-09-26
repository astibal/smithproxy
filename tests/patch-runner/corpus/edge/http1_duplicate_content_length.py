from _common import script

PPlayScript = script("http1_duplicate_content_length", [
    b"POST /duplicate-length HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ntest",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
], "cs")
