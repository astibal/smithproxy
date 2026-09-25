from _common import script

query = bytes.fromhex("123401000001000000000000076578616d706c6504746573740000010001")
answer = bytes.fromhex("123481800001000100000000076578616d706c6504746573740000010001c00c000100010000003c0004c0000201")
PPlayScript = script("dns_over_tcp", [len(query).to_bytes(2, "big") + query, len(answer).to_bytes(2, "big") + answer], "cs")
