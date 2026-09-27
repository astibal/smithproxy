from _common import script

PPlayScript = script("http1_interim_responses", [
    b"GET /hints HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n",
    b"HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
], "cs")
