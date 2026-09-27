from _common import H2_PREFACE, h2_settings, script

PPlayScript = script("protocol_collision", [
    b"GET /first HTTP/1.1\r\nHost: origin.runner.lab\r\n\r\n" + H2_PREFACE + h2_settings(),
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" + h2_settings(),
], "cs")
