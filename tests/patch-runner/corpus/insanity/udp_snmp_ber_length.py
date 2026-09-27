from _common import script

PPlayScript = script("udp_snmp_ber_length", [
    b"\x30\x84\xff\xff\xff\xff\x02\x01\x01\x04\x06public",
    b"\x30\x03\x02\x01\x00",
], "cs")
