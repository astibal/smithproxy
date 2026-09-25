from _common import dns_query, script

query = dns_query("example.test", qtype=16, ident=0x5458)
txt = b"v=spf1 -all"
answer = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + (len(txt) + 1).to_bytes(2, "big") + bytes((len(txt),)) + txt
PPlayScript = script("udp_dns_txt", [query, answer], "cs")
