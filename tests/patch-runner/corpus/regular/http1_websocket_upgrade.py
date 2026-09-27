from _common import script

PPlayScript = script("http1_websocket_upgrade", [
    b"GET /chat HTTP/1.1\r\nHost: origin.runner.lab\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    b"\x81\x82\x01\x02\x03\x04\x69\x6b",
    b"\x81\x02hi",
], "cscs")
