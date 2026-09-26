from _common import script

PPlayScript = script("http1_split_request_line", [
    b"GE", b"T /split HT", b"TP/1.1\r\n", b"Host: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
], "ccccs")
