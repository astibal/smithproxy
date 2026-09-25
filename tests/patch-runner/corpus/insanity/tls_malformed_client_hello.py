from _common import script

record = b"\x16\x03\x03\xff\xff\x01\x00\x00\x08" + b"\x03\x03" + b"short"
alert = b"\x15\x03\x03\x00\x02\x02\x32"
PPlayScript = script("tls_malformed_client_hello", [record, alert], "cs")
