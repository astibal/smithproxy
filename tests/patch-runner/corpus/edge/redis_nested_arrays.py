from _common import script

PPlayScript = script("redis_nested_arrays", [
    b"*2\r\n$4\r\nECHO\r\n*3\r\n:1\r\n$3\r\ntwo\r\n*-1\r\n",
    b"*3\r\n:1\r\n$3\r\ntwo\r\n*-1\r\n",
], "cs")
