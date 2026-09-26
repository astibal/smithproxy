from _common import dns_query, script

query = dns_query("length.example.test", ident=0x4004)
PPlayScript = script("dns_tcp_length_mismatch", [
    b"\xff\xff" + query,
    b"\x00\x0c\x40\x04\x81\x81\x00\x00\x00\x00\x00\x00\x00\x00",
], "cs")
