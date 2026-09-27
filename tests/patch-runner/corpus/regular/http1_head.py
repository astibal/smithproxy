from _common import script

PPlayScript = script("http1_head", [
    b"HEAD /status HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nDate: Tue, 22 Sep 2026 00:00:00 GMT\r\n\r\n",
], "cs")
