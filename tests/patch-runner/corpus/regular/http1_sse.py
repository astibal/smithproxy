from _common import script

body = b"event: ready\nid: 1\ndata: hello\n\nevent: done\ndata: bye\n\n"
PPlayScript = script("http1_sse", [
    b"GET /events HTTP/1.1\r\nHost: origin.runner.lab\r\nAccept: text/event-stream\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
], "cs")
