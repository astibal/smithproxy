from _common import script

PPlayScript = script("redis_negative_array", [b"*-2\r\n$-999\r\n", b"-ERR invalid multibulk length\r\n"], "cs")
