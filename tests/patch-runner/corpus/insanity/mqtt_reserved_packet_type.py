from _common import script

PPlayScript = script("mqtt_reserved_packet_type", [b"\x00\x00", b"\xf0\x00", b"\xff\x00"], "csc")
