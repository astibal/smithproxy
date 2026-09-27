from _common import dns_query, script

query = bytearray(dns_query("one.test", ident=0x5151)); query[4:6] = b"\x00\x05"
PPlayScript = script("udp_dns_question_count_mismatch", [bytes(query), bytes(query[:2]) + b"\x81\x81\x00\x00\x00\x00\x00\x00\x00\x00"], "cs")
