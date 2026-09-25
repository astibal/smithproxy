from _common import script

PPlayScript = script("http1_response_without_status", [
    b"GET /statusless HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"Content-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
], "cs")
