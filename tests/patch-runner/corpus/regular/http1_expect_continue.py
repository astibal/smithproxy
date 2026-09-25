from _common import script

PPlayScript = script("http1_expect_continue", [
    b"POST /large HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\n",
    b"hello",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
], "cscs")
