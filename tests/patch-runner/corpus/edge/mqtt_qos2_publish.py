from _common import script

publish = b"\x34\x0c\x00\x05topic\x12\x34data"
PPlayScript = script("mqtt_qos2_publish", [publish, b"\x50\x02\x12\x34", b"\x62\x02\x12\x34", b"\x70\x02\x12\x34"], "cscs")
