from _common import script

PPlayScript = script("http1_keepalive", [
    b"GET /one HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none",
    b"GET /two HTTP/1.1\r\nHost: origin.runner.lab\r\nConnection: close\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
], "cscs")
