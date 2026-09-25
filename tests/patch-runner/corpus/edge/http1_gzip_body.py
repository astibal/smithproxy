from _common import script

gzip_member = bytes.fromhex("1f8b0800000000000003cb48cdc9c9070086a6103605000000")
PPlayScript = script("http1_gzip_body", [
    b"GET /gzip HTTP/1.1\r\nHost: origin.runner.lab\r\nAccept-Encoding: gzip\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + str(len(gzip_member)).encode() + b"\r\n\r\n" + gzip_member,
], "cs")
