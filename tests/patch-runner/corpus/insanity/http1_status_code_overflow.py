from _common import script

PPlayScript = script("http1_status_code_overflow", [
    b"GET /status HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 999999999999999999999999 strange\r\nContent-Length: 0\r\n\r\n",
], "cs")
