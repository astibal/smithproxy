from _common import dns_query, script

query = dns_query("www.example.test", ident=0x434E)
response = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x08\x05alias\xc0\x10"
PPlayScript = script("dns_tcp_cname", [len(query).to_bytes(2, "big") + query, len(response).to_bytes(2, "big") + response], "cs")
