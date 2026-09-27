from _common import script

PPlayScript = script("http1_absolute_uri", [
    b"GET http://origin.runner.lab:8080/path?q=1 HTTP/1.1\r\nHost: origin.runner.lab:8080\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
], "cs")
