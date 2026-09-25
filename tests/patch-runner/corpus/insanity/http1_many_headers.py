from _common import script

headers = b"".join(b"X-%03d: value-%03d\r\n" % (i, i) for i in range(128))
PPlayScript = script("http1_many_headers", [
    b"GET /many HTTP/1.1\r\nHost: origin.runner.lab\r\n" + headers + b"\r\n",
    b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n",
], "cs")
