from _common import script

PPlayScript = script("http1_204_keepalive", [
    b"GET /empty HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nContent-Length: 123\r\nConnection: keep-alive\r\n\r\n",
    b"GET /next HTTP/1.1\r\nHost: origin.runner.lab\r\nConnection: close\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnext",
], "cscs")
