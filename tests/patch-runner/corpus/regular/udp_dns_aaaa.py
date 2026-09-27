from _common import dns_name, dns_query, script

question = dns_name("v6.example.test") + b"\x00\x1c\x00\x01"
answer = b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + bytes.fromhex("20010db8000000000000000000000001")
response = b"\x12\x35\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer
PPlayScript = script("udp_dns_aaaa", [dns_query("v6.example.test", 28, 0x1235), response], "cs")
