from _common import script

PPlayScript = script("telnet_negotiation", [
    b"\xff\xfb\x01\xff\xfb\x03login: ", b"alice\r\n",
    b"Password: ", b"secret\r\n", b"Welcome\r\n$ ", b"exit\r\n", b"logout\r\n",
], "scscscs")
