from _common import script

PPlayScript = script("socks5_invalid_address_type", [b"\x05\x01\x00", b"\x05\x00", b"\x05\x01\x00\xffgarbage", b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00"], "cscs")
