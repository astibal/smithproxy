from _common import script

query = b"\x40\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01"
response = query[:2] + b"\x81\x81" + query[4:]
PPlayScript = script("udp_dns_pointer_loop", [query, response], "cs")
