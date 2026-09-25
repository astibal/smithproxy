from _common import script

params = b"user\x00alice\x00database\x00app\x00client_encoding\x00UTF8\x00\x00"
startup = (8 + len(params)).to_bytes(4, "big") + b"\x00\x03\x00\x00" + params
PPlayScript = script("postgresql_startup", [startup, b"R\x00\x00\x00\x08\x00\x00\x00\x00Z\x00\x00\x00\x05I"], "cs")
