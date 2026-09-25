from _common import script

PPlayScript = script("websocket_frames", [
    b"GET /chat HTTP/1.1\r\nHost: origin.runner.lab\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: BACScCJPNqyz+UBoqMH89VmURoA=\r\n\r\n",
    b"\x81\x85\x01\x02\x03\x04igohn\x89\x80\x05\x06\x07\x08",
    b"\x81\x05world\x8a\x00",
], "cscs")
