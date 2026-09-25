from _common import dns_answer_a, dns_query, script

PPlayScript = script("udp_dns_a", [dns_query(), dns_answer_a()], "cs")
