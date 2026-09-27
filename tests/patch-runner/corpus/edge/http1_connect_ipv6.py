from _common import script

PPlayScript = script("http1_connect_ipv6", [
    b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n",
    b"HTTP/1.1 200 Connection Established\r\n\r\n",
    b"opaque tunnel bytes\x00\x01\x02",
    b"opaque reply\xff\xfe",
], "cscs")
