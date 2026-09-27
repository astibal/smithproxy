from _common import script

PPlayScript = script("binary_roundtrip", [
    bytes(range(256)),
    bytes(reversed(range(256))),
], "cs")
