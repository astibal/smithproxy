from _common import script

PPlayScript = script("mqtt_remaining_length_overflow", [
    b"\x30\xff\xff\xff\xff\x7fshort",
    b"\x40\x02\x00\x00",
], "cs")
