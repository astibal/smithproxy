from _common import script

connect = bytes.fromhex("101000044d5154540402003c000470706c79")
connack = bytes.fromhex("20020000")
publish = b"0\x0c\x00\x05topicpayload"
PPlayScript = script("mqtt_connect_publish", [connect, connack, publish, b"\x40\x02\x00\x01"], "cscs")
