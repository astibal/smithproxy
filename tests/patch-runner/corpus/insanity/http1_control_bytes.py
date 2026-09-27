from _common import script

PPlayScript = script("http1_control_bytes", [
    b"GET /controls HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Control: \x01\x02\x07\x08\x0b\x0c\x1f\x7f\r\n\r\n",
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 1\r\n\r\n!",
], "cs")
