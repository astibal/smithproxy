from _common import script

cookie = b"\x21\x12\xa4\x42"
txid = b"pplay-stun12"
request = b"\x00\x01\x00\x00" + cookie + txid
response = b"\x01\x01\x00\x0c" + cookie + txid + b"\x00\x20\x00\x08\x00\x01\xe2\x42\xe1\x12\xa6\x43"
PPlayScript = script("udp_stun_binding", [request, response], "cs")
