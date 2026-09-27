from _common import dns_query, script

query = dns_query("", qtype=2, ident=0x0001)
response = query[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:]
PPlayScript = script("udp_dns_root_query", [query, response], "cs")
