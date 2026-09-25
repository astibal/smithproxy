from _common import script

PPlayScript = script("http1_absurd_content_length", [
    b"POST /claimed-huge HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Length: 18446744073709551615\r\n\r\nx",
    b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n",
], "cs")
