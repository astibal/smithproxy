from _common import dns_query, script

name = "a" * 63 + "." + "b" * 63 + ".test"
query = dns_query(name, ident=0x3002)
response = query[:2] + b"\x81\x83" + query[4:]
PPlayScript = script("udp_dns_max_label", [query, response], "cs")
