from _common import script

body = b"alpha=one&beta=two+words"
PPlayScript = script("http1_post_form", [
    b"POST /submit HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "
    + str(len(body)).encode() + b"\r\n\r\n" + body,
    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nsaved\r\n",
], "cs")
