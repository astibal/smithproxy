from _common import dns_name, dns_query, script

question = dns_name("missing.example.test") + b"\x00\x01\x00\x01"
response = b"\x12\x36\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + question
PPlayScript = script("udp_dns_nxdomain", [dns_query("missing.example.test", 1, 0x1236), response], "cs")
