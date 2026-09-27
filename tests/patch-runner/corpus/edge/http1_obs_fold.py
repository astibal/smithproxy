from _common import script

PPlayScript = script("http1_obs_fold", [
    b"GET /fold HTTP/1.1\r\nHost: origin.runner.lab\r\nX-Long: first\r\n second\r\n\tthird\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
], "cs")
