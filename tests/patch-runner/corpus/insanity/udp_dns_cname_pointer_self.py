from _common import dns_query, script

query = dns_query("loop.test", ident=0xC0DE)
answer = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x01\x00\x02\xc0\x27"
PPlayScript = script("udp_dns_cname_pointer_self", [query, answer], "cs")
