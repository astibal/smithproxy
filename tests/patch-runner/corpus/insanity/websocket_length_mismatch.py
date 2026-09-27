from _common import script

PPlayScript = script("websocket_length_mismatch", [
    b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: eA==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    b"\x82\x7f\x7f\xff\xff\xff\xff\xff\xff\xfftiny",
], "csc")
