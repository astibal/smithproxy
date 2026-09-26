from _common import script

boundary = b"----pplay-boundary"
body = b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--" + boundary + b"--\r\n"
PPlayScript = script("http1_multipart_form", [
    b"POST /form HTTP/1.1\r\nHost: origin.runner.lab\r\nContent-Type: multipart/form-data; boundary=" + boundary
    + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
], "cs")
