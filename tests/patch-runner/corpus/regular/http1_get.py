from _common import script

PPlayScript = script("http1_get", [
    b"GET / HTTP/1.1\r\nHost: origin.runner.lab\r\nConnection: close\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
], "cs")
