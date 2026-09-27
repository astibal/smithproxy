from _common import script

PPlayScript = script("http1_delete", [
    b"DELETE /items/42 HTTP/1.1\r\nHost: origin.runner.lab\r\nAccept: application/json\r\n\r\n",
    b"HTTP/1.1 202 Accepted\r\nContent-Length: 12\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}\n",
], "cs")
