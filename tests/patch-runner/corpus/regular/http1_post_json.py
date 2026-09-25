from _common import script

body = b'{"enabled":true,"count":3}'
PPlayScript = script("http1_post_json", [
    b"POST /api/items HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Type: application/json\r\nContent-Length: "
    + str(len(body)).encode() + b"\r\n\r\n" + body,
    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nLocation: /api/items/7\r\n\r\n",
], "cs")
