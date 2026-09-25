from _common import dns_answer_a, dns_query, script

q1 = dns_query("one.example.test", ident=0x2001)
q2 = dns_query("two.example.test", qtype=28, ident=0x2002)
r1 = dns_answer_a("one.example.test", ident=0x2001)
r2 = dns_answer_a("two.example.test", address=b"\xc0\x00\x02\x02", ident=0x2002)
PPlayScript = script("dns_tcp_two_messages", [
    len(q1).to_bytes(2, "big") + q1 + len(q2).to_bytes(2, "big") + q2,
    len(r1).to_bytes(2, "big") + r1 + len(r2).to_bytes(2, "big") + r2,
], "cs")
