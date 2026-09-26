from _common import script

request = b"\x23" + b"\x00" * 47
response = b"\x24\x02\x04\xec" + b"\x00\x00\x00\x20" + b"\x00" * 40
PPlayScript = script("udp_ntp", [request, response], "cs")
