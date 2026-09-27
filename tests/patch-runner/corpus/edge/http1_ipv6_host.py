from _common import script

PPlayScript = script("http1_ipv6_host", [
    b"GET /v6 HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nv6",
], "cs")
