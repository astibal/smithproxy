from _common import script

PPlayScript = script("http1_lf_only", [
    b"GET /lf HTTP/1.1\nHost: origin.runner.lab\n\n",
    b"HTTP/1.1 200 OK\nContent-Length: 3\n\nok\n",
], "cs")
