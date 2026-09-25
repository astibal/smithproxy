from _common import script

PPlayScript = script("mqtt_fragmented_publish", [
    b"0", b"\x0c", b"\x00\x05", b"topic", b"payload",
    b"\x40", b"\x02\x00\x01",
], "cccccss")
