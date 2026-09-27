from _common import script

body = bytes(range(256)) * 8
PPlayScript = script("http1_binary_body", [
    b"POST /binary HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Type: application/octet-stream\r\nContent-Length: "
    + str(len(body)).encode() + b"\r\n\r\n" + body,
    b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n" + body[:32],
], "cs")
