from _common import script

name = b"X" * 16384
PPlayScript = script("http1_header_name_16k", [
    b"GET /header-name HTTP/1.1\r\nHost: origin.runner.lab\r\n" + name + b": value\r\n\r\n",
    b"HTTP/1.1 431 Too Large\r\nContent-Length: 0\r\n\r\n",
], "cs")
