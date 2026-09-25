from _common import script

body = b"replacement document\n"
PPlayScript = script("http1_put", [
    b"PUT /document.txt HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
], "cs")
