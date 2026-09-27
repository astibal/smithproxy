from _common import script

PPlayScript = script("http1_conflicting_lengths", [
    b"POST /conflict HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Length: 4\r\nContent-Length: 9\r\n\r\ntest",
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
], "cs")
