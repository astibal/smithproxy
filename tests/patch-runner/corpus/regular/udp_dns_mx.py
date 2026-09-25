from _common import dns_query, script

query = dns_query("example.test", qtype=15, ident=0x4D58)
answer = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + b"\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x09\x00\x0a\x04mail\xc0\x0c"
PPlayScript = script("udp_dns_mx", [query, answer], "cs")
