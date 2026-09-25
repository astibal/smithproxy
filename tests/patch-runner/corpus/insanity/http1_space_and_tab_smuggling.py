from _common import script

PPlayScript = script("http1_space_and_tab_smuggling", [
    b"GET\t/one\tHTTP/1.1\r\nHost : origin.runner.lab\r\nTransfer-Encoding : chunked\r\n Content-Length: 4\r\n\r\n0\r\n\r\n",
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
], "cs")
