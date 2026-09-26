from _common import dns_query, script

query = dns_query("alias.example.test", 5, 0x3003)
answer = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0c"
response = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + answer
PPlayScript = script("udp_dns_compressed_answer", [query, response], "cs")
