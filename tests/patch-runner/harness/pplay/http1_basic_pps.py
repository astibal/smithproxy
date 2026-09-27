"""Minimal deterministic HTTP/1 exchange for the Smithproxy runner."""


class PPlayScript:
    def __init__(self, pplay, args=None):
        self.pplay = pplay
        self.args = args
        self.server_port = 18080

        request = (
            b"GET /pplay-smoke HTTP/1.1\r\n"
            b"Host: origin.runner.lab\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        response_body = b"pplay-ok\n"
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 9\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            + response_body
        )

        self.packets = [request, response]
        self.origins = {"client": [0], "server": [1]}

        # pplay's script loader reads these attributes even without --ssl.
        self.ssl_cert = None
        self.ssl_key = None
        self.ssl_ca_cert = None
        self.ssl_ca_key = None

    def before_send(self, role, index, data):
        return None

    def after_received(self, role, index, data):
        return None
