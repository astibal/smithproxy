from _common import script

cookie = b"\x21\x12\xa4\x42"
txid = b"edge-stun-12"
attrs = b"\x00\x06\x00\x05user1\x00\x00\x00\x80\x22\x00\x04test"
request = b"\x00\x01" + len(attrs).to_bytes(2, "big") + cookie + txid + attrs
response = b"\x01\x11\x00\x00" + cookie + txid
PPlayScript = script("udp_stun_attributes", [request, response], "cs")
